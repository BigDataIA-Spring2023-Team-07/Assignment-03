import typer
import boto3
import os
from dotenv import load_dotenv
import sqlite3
from pathlib import Path
import pandas as pd


env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

app = typer.Typer()




def create_connection():

    """
    Create a connection to AWS S3 bucket

    Returns:
        s3client: boto3 client object

    """

    s3client = boto3.client('s3',
    region_name= "us-east-1",
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY1'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_KEY1'))

    return s3client




@app.command()
def createuser(user_name: str):
    """ 
    Create a user in the system
    """

    tier_lst = ["free", "gold", "platium"]

    password = typer.prompt("Enter password", hide_input=True)
    confirm_password = typer.prompt("Confirm password", hide_input=True)

    if password != confirm_password:
        typer.echo("Passwords do not match")
        return
    
    if password == "":
        typer.echo("Password cannot be empty")
        return
    
    if password == confirm_password:
        user_tier = typer.prompt("Select the tier you want to use \n 1. Free \n 2. Gold \n 3. Platium", type=int)
        if user_tier not in [1, 2, 3]:
            typer.echo("Invalid tier selection")
            return
    
        df = pd.DataFrame({"user_name": [user_name], "password": [password], "tier": [user_tier]})
        df.to_sql("users", con=sqlite3.connect("users.db"), if_exists="append", index=False)
        typer.echo(f"User {user_name} created successfully")




@app.command()
def fetch(user_name: str, bucket_name:str):
               
    """
    List all files in an S3 bucket
    """

    s3client = create_connection()

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    users = pd.read_sql_query("SELECT * FROM users", connection)
    user_lst = users["user_name"].tolist()

    if user_name not in user_lst:
        typer.echo(f"User {user_name} does not exist")
        return
    

    typer.confirm(f"Are you sure you want to list files in S3 bucket?", abort=True)
    typer.echo("Listing files in S3 bucket.........")
    objects = s3client.list_objects_v2(Bucket=bucket_name)

    for obj in objects.get("Contents", []):
        typer.echo(obj.get("Key"))


@app.command()
def download(user_name: str, bucket_name: str = typer.Argument("damg7245-team7"), file_name: str = typer.Argument(...)):
    """
    Download a file from an S3 bucket
    """
    s3client = create_connection()

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    users = pd.read_sql_query("SELECT * FROM users", connection)
    user_lst = users["user_name"].tolist()

    if user_name not in user_lst:
        typer.echo(f"User {user_name} does not exist")
        return
    

    # Check if the file exists in the bucket
    objects = s3client.list_objects_v2(Bucket=bucket_name)
    if not any(obj.get("Key") == file_name for obj in objects.get("Contents", [])):
        typer.echo(f"File '{file_name}' does not exist in S3 bucket '{bucket_name}'.")
        return
    
    # Download the file
    typer.echo(f"Downloading file '{file_name}' from S3 bucket '{bucket_name}'...")
    s3client.download_file(bucket_name, file_name, file_name)


if __name__ == "__main__":
    app()