from backend import schema
from fastapi import FastAPI,Depends,Response,status
import sqlite3
import os
import pandas as pd
from passlib.context import CryptContext
from backend import access_token
from backend import oauth2
from fastapi.security import OAuth2PasswordRequestForm
import re
import requests
import boto3
import logging
import time
import sys
from datetime import datetime,timedelta


project_dir = os.getcwd()
sys.path.insert(0, project_dir)
os.environ.get('PYTHONPATH', '')
os.environ['PYTHONPATH'] = project_dir + ':' + os.environ.get('PYTHONPATH', '')

from backend import main_goes18, goes_file_retrieval_main
from backend import main_goes18, goes_file_retrieval_main, nexrad_file_retrieval_main
from pydantic import BaseModel
import random
import string
from backend import nexrad_main

from api_codes.goes_api import router as goes_router
from api_codes.nexrad_api import router as nexrad_router
from api_codes.s3_api import router as s3_router
from api_codes.login import router as login_router

app = FastAPI()

app.include_router(goes_router)
app.include_router(nexrad_router)
app.include_router(s3_router)
app.include_router(login_router)


clientlogs = boto3.client('logs',
region_name= "us-east-1",
aws_access_key_id=os.environ.get('AWS_LOG_ACCESS_KEY'),
aws_secret_access_key=os.environ.get('AWS_LOG_SECRET_KEY'))

def create_connection():
    
    """AWS connnetion using boto3

    Returns:
        s3client: aws client id
    """
    
    write_logs("starting connection to s3")
    s3client = boto3.client('s3',
                        region_name='us-east-1',
                        aws_access_key_id = os.environ.get('AWS_ACCESS_KEY'),
                        aws_secret_access_key = os.environ.get('AWS_SECRET_KEY')
                        )
    write_logs("connected to s3")

    return s3client

def write_logs(message):
    
    """Writes the logs to the cloudwatch logs

    Args:
        message (str): The message to be written to the logs
    """
    
    clientlogs.put_log_events (
    logGroupName="assignment_01",
    logStreamName="app_logs",
    logEvents=[
        {
    'timestamp' : int(time.time()* 1e3),
    'message': message,
    }
    ]
    )

@app.get('/goes_station')
async def grab_station(getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    """for pulling all the stations in the file from database

    Returns:
        stations_list: list of stations
    """
    stations=main_goes18.grab_station()
    
    return {'Stations':stations}


@app.get('/goes_years')
async def grab_years(user_station: schema.goes_year, getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    """for pulling all the years in the station from database

    Args:
        station (string): station name

    Returns:
        year_list: list of all the years for a particular station
    """
    # 
    
    if not re.match(r"[A-Za-z0-9\.,;:!?()\"'%\-]+",user_station.station):
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    else:
        
        year_list=main_goes18.grab_years(user_station.station)    
        
        return {'Year':year_list}

@app.get('/goes_days')
async def grab_months(user_day: schema.goes_day, getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    """for pulling all the days in the particular station,year from database

    Args:
        station (str): station
        years (str): year

    Returns:
        day_list: list of days for a particular station,year
    """
    
    if not re.match(r"[A-Za-z0-9\.,;:!?()\"'%\-]+",user_day.station):
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_day.year)<2022 or int(user_day.year)>2023:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    else:
        
        day_list=main_goes18.grab_days(user_day.station,user_day.year)
        return {'Day':day_list}

@app.get('/goes_hours')
async def grab_hours(user_hour: schema.goes_hour, getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    
    """for pulling all the hours in the file for a particular station,year,day

    Args:
        station (str): station name
        years (str): year
        days (str): day

    Returns:
        hour_list: list of all hours in the file for a particular station,year,day
    """
    
    if not re.match(r"[A-Za-z0-9\.,;:!?()\"'%\-]+",user_hour.station):
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_hour.year)<2022 or int(user_hour.year)>2023:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_hour.day)<1 or int(user_hour.day)>365:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    else:
        hour_list=main_goes18.grab_hours(user_hour.station,user_hour.year,user_hour.day)
        return {'Hour':hour_list}

@app.get('/goes_files')
async def grab_files(user_files: schema.goes_file, getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    """pulls files from noaa18 aws bucket for a set of station, year,day,hour

    Args:
        station (str): station name
        years (str): year
        days (str): day
        hours (str): hour

    Returns:
        file_names: list of files present in noaa18 aws bucket for a set of station, year,day,hour
    """
    
    # client_id=create_connection()
    
    # write_logs("fetching Files in list from NOAA bucket")
    if not re.match(r"[A-Za-z0-9\.,;:!?()\"'%\-]+",user_files.station):
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_files.year)<2022 or int(user_files.year)>2023:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_files.day)<1 or int(user_files.day)>365:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_files.hour)<0 or int(user_files.hour)>24:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
        
    else:
        files_list=main_goes18.grab_files(user_files.station,user_files.year,user_files.day,user_files.hour)
        return {"Files":files_list}


@app.post('/goes_fetch_url')
async def create_url(user_url: schema.goes_url, getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    
    if not re.match(r"[A-Za-z0-9\.,;:!?()\"'%\-]+",user_url.station):
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_url.year)<2022 or int(user_url.year)>2023:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_url.day)<1 or int(user_url.day)>365:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_url.hour)<0 or int(user_url.hour)>24:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if not goes_file_retrieval_main.validate_file(user_url.file) == 'Valid filename':
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    else:
        
        url=main_goes18.create_url(user_url.station,user_url.year,user_url.day,user_url.hour,user_url.file)
        
        response = requests.get(url)
        
        if response.status_code == 200:
            return {'NOAAURL': url}
        else:
            return Response(status_code=status.HTTP_404_NOT_FOUND)
        
@app.post('/goes_AWS_url')
async def s3_url(user_purl: schema.goes_url, getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
     
    if not re.match(r"[A-Za-z0-9\.,;:!?()\"'%\-]+",user_purl.station):
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_purl.year)<2022 or int(user_purl.year)>2023:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_purl.day)<1 or int(user_purl.day)>365:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if int(user_purl.hour)<0 or int(user_purl.hour)>24:
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    if not goes_file_retrieval_main.validate_file(user_purl.file) == 'Valid filename':
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    
    else:
        
        key = main_goes18.generate_key(user_purl.station,user_purl.year,user_purl.day,user_purl.hour,user_purl.file)
        url=main_goes18.copy_files_s3(key,user_purl.file)
        
        response = requests.get(url)
        
        if response.status_code == 200:
            return {'S3URL': url}
        else:
            return Response(status_code=status.HTTP_404_NOT_FOUND)


@app.post("/validatefileUrl")
async def validate_file(validateFile: schema.ValidateFile,getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
  filename = validateFile.file_name
  write_logs("Entered file validation function")
  products = ['ABI-L1b-RadF', 'ABI-L1b-RadC', 'ABI-L1b-RadM', 'ABI-L2-ACHAC','ABI-L2-ACHAF','ABI-L2-ACHAM','ABI-L2-ACHTF',
             'ABI-L2-ACHTM','ABI-L2-ACMC','ABI-L2-ACMF','ABI-L2-ACMM','ABI-L2-ACTPC','ABI-L2-ACTPM','ABI-L2-ACTPF','ABI-L2-ADPM','ABI-L2-AICEF',
             'ABI-L2-AITAF','ABI-L2-AODC','ABI-L2-AODF','ABI-L2-BRFC','ABI-L2-BRFF','ABI-L2-BRFM','ABI-L2-CMIPC','ABI-L2-CMIPF',
             'ABI-L2-CMIPM','ABI-L2-CODC','ABI-L2-CODF','ABI-L2-CPSC','ABI-L2-CPSF','ABI-L2-CPSM','ABI-L2-CTPC','ABI-L2-CTPF','ABI-L2-DMWC',
             'ABI-L2-DMWF','ABI-L2-DMWM','ABI-L2-DMWVC','ABI-L2-DMWVF','ABI-L2-DMWVM','ABI-L2-DSIC','ABI-L2-DSIF','ABI-L2-DSIM','ABI-L2-DSRC',
             'ABI-L2-DSRF','ABI-L2-DSRM','ABI-L2-FDCC','ABI-L2-FDCF','ABI-L2-FDCM','ABI-L2-LSAC','ABI-L2-LSAF','ABI-L2-LSAM','ABI-L2-LSTC',
             'ABI-L2-LSTF','ABI-L2-LSTM','ABI-L2-LVMPC','ABI-L2-LVMPF','ABI-L2-LVMPM','ABI-L2-LVTPC','ABI-L2-LVTPF','ABI-L2-LVTPM','ABI-L2-MCMIPC',
             'ABI-L2-MCMIPF','ABI-L2-MCMIPM','ABI-L2-RRQPEF','ABI-L2-RSRC','ABI-L2-RSRF','ABI-L2-SSTF','ABI-L2-TPWC','ABI-L2-TPWF','ABI-L2-TPWM',
             'ABI-L2-VAAF','EXIS-L1b-SFEU','EXIS-L1b-SFXR','GLM-L2-LCFA','MAG-L1b-GEOF','SEIS-L1b-EHIS','SEIS-L1b-MPSH','SEIS-L1b-MPSL','SEIS-L1b-SGPS',
             'SUVI-L1b-Fe093','SUVI-L1b-Fe131','SUVI-L1b-Fe171','SUVI-L1b-Fe195','SUVI-L1b-Fe284','SUVI-L1b-He303']
  
  productLengths = []

  for product in products:
    productLen = len(product)
    if productLen not in productLengths:
      productLengths.append(productLen)
  
  file_name_split = filename.split('_')

  if(len(file_name_split)>6):
    write_logs("File name is invalid")
    write_logs("File validation function execution complete")
    data = {'message': 'File name is invalid','status_code': '200'}
    return data

  if file_name_split[0] != 'OR':
    write_logs("File name should start with OR")
    write_logs("File validation function execution complete")
    data = {'message': 'File name should start with OR', 'status_code': '200'}
    return data

  x=0
  for i in productLengths:
    if len(file_name_split[1])>=i:
      if file_name_split[1][0:i-1] in products:
        x=1
        
  if x!=1:
    write_logs("Product name specified is invalid")
    write_logs("File validation function execution complete")
    data = {'message': 'Product name specified is invalid', 'status_code': '200'}
    return data
  
  productVersion = file_name_split[1].split('-')[-1:][0]
  if len(productVersion)==2:
    if productVersion[0]!='M' or (not productVersion[1].isnumeric()):
      write_logs("Mode or channel number error")
      write_logs("File validation function execution complete")
      data = {'message': 'Mode or channel number error', 'status_code': '200'}
      return data
  elif len(productVersion)==5:
    if productVersion[0]!='M' or productVersion[2]!='C' or (not productVersion[1].isnumeric()) or (not productVersion[3:5].isnumeric()):
      write_logs("Mode or channel number error")
      write_logs("File validation function execution complete")
      data = {'message': 'Mode or channel number error', 'status_code': '200'}
      return data
  else:
    write_logs("Mode or channel number error")
    write_logs("File validation function execution complete")
    data = {'message': 'Mode or channel number error', 'status_code': '200'}
    return data

  if file_name_split[2][0]!='G' or (not file_name_split[2][1:3].isnumeric()):
    write_logs("Goes number specification error")
    write_logs("File validation function execution complete")
    data = {'message': 'Goes number specification error', 'status_code': '200'}
    return data
  elif file_name_split[2][1:3].isnumeric():
    if int(file_name_split[2][1:3])>18:
      write_logs("Goes number specification error")
      write_logs("File validation function execution complete")
      data = {'message': 'Goes number specification error', 'status_code': '200'}
      return data

  if len(file_name_split[3])==15 and file_name_split[3][0]=='s' and file_name_split[3][1:].isnumeric():
    if int(file_name_split[3][1:5])>2023 or int(file_name_split[3][5:8])>366 or int(file_name_split[3][8:10])>24 or int(file_name_split[3][10:12])>60 or int(file_name_split[3][12:14])>60:
      write_logs("Scan time specified is in incorrect format")
      write_logs("File validation function execution complete")
      data = {'message': 'Scan time specified is in incorrect format', 'status_code': '200'}
      return data
  else:
    write_logs("Scan time specified is in incorrect format")
    write_logs("File validation function execution complete")
    data = {'message': 'Scan time specified is in incorrect format', 'status_code': '200'}
    return data

  if len(file_name_split[4])==15 and file_name_split[4][0]=='e' and file_name_split[4][1:].isnumeric():
    if int(file_name_split[4][1:5])>2023 or int(file_name_split[4][5:8])>366 or int(file_name_split[4][8:10])>24 or int(file_name_split[4][10:12])>60 or int(file_name_split[4][12:14])>60:
      write_logs("End time specified is in incorrect format")
      write_logs("File validation function execution complete")
      data = {'message': 'End time specified is in incorrect format', 'status_code': '200'}
      return data
  else:
    write_logs("End time specified is in incorrect format")
    write_logs("File validation function execution complete")
    data = {'message': 'End time specified is in incorrect format', 'status_code': '200'}
    return data

  file_name_split[5]=file_name_split[5].replace(" ","")
  if file_name_split[5][15:18]!='.nc':
    data = {'message': 'File name should end with .nc only', 'status_code': '200'}
    return data
  
  if len(file_name_split[5])==18 and file_name_split[5][0]=='c' and file_name_split[5][1:15].isnumeric() and file_name_split[5][15:18]=='.nc':
    if int(file_name_split[5][1:5])>2023 or int(file_name_split[5][5:8])>366 or int(file_name_split[5][8:10])>24 or int(file_name_split[5][10:12])>60 or int(file_name_split[5][12:14])>60:
      write_logs("File creation time specified is in incorrect format")
      write_logs("File validation function execution complete")
      data = {'message': 'File creation time specified is in incorrect format', 'status_code': '200'}
      return data
  else:
    write_logs("File creation time specified is in incorrect format")
    write_logs("File validation function execution complete")
    data = {'message': 'File creation time specified is in incorrect format', 'status_code': '200'}
    return data

  write_logs("Valid filename")
  write_logs("File validation function execution complete")
  data = {'message': 'Valid filename', 'status_code': '200'}
  return data

@app.post("/login")
async def login(login_data: OAuth2PasswordRequestForm = Depends()):
    try:
        database_file_name = "assignment_01.db"
        database_file_path = os.path.join('data/',database_file_name)
        db = sqlite3.connect(database_file_path)
        user= pd.read_sql_query('SELECT * FROM Users where username="{}"'.format(login_data.username), db)
        if len(user) == 0:
           data = {"message": "User not found", "status_code": "404"}
        else:
            pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")
            if pwd_cxt.verify(login_data.password, user['hashed_password'][0]):
                data = {'message': 'Username verified successfully', 'status_code': '200'}
                accessToken = access_token.create_access_token(data={"sub": str(user['username'][0])})
                data = {'message': 'Username verified successfully','access_token': accessToken,'service_plan': user['service_plan'][0],'status_code': '200'}
            else:
                data = {'message': 'Password is incorrect' ,'status_code': '401'}
    except Exception as e:
        print("Exception occured in login function")
        data = {'message': str(e),'status_code': '500'}
    return data

@app.post("/getfileUrl")
async def getFileUrl(validateFile: schema.ValidateFile, getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    filename = validateFile.file_name
    write_logs("Get file url function entered")

    base_url="https://noaa-goes"+filename.split('_')[2][1:3]+".s3.amazonaws.com/"
    timestamp = filename.split('_')[-3].split(".")[0]
    timestamp

    products = ['ABI-L1b-RadF', 'ABI-L1b-RadC', 'ABI-L1b-RadM', 'ABI-L2-ACHAC','ABI-L2-ACHAF','ABI-L2-ACHAM','ABI-L2-ACHTF',
                'ABI-L2-ACHTM','ABI-L2-ACMC','ABI-L2-ACMF','ABI-L2-ACMM','ABI-L2-ACTPC','ABI-L2-ACTPM','ABI-L2-ACTPF','ABI-L2-ADPM','ABI-L2-AICEF',
                'ABI-L2-AITAF','ABI-L2-AODC','ABI-L2-AODF','ABI-L2-BRFC','ABI-L2-BRFF','ABI-L2-BRFM','ABI-L2-CMIPC','ABI-L2-CMIPF',
                'ABI-L2-CMIPM','ABI-L2-CODC','ABI-L2-CODF','ABI-L2-CPSC','ABI-L2-CPSF','ABI-L2-CPSM','ABI-L2-CTPC','ABI-L2-CTPF','ABI-L2-DMWC',
                'ABI-L2-DMWF','ABI-L2-DMWM','ABI-L2-DMWVC','ABI-L2-DMWVF','ABI-L2-DMWVM','ABI-L2-DSIC','ABI-L2-DSIF','ABI-L2-DSIM','ABI-L2-DSRC',
                'ABI-L2-DSRF','ABI-L2-DSRM','ABI-L2-FDCC','ABI-L2-FDCF','ABI-L2-FDCM','ABI-L2-LSAC','ABI-L2-LSAF','ABI-L2-LSAM','ABI-L2-LSTC',
                'ABI-L2-LSTF','ABI-L2-LSTM','ABI-L2-LVMPC','ABI-L2-LVMPF','ABI-L2-LVMPM','ABI-L2-LVTPC','ABI-L2-LVTPF','ABI-L2-LVTPM','ABI-L2-MCMIPC',
                'ABI-L2-MCMIPF','ABI-L2-MCMIPM','ABI-L2-RRQPEF','ABI-L2-RSRC','ABI-L2-RSRF','ABI-L2-SSTF','ABI-L2-TPWC','ABI-L2-TPWF','ABI-L2-TPWM',
                'ABI-L2-VAAF','EXIS-L1b-SFEU','EXIS-L1b-SFXR','GLM-L2-LCFA','MAG-L1b-GEOF','SEIS-L1b-EHIS','SEIS-L1b-MPSH','SEIS-L1b-MPSL','SEIS-L1b-SGPS',
                'SUVI-L1b-Fe093','SUVI-L1b-Fe131','SUVI-L1b-Fe171','SUVI-L1b-Fe195','SUVI-L1b-Fe284','SUVI-L1b-He303']
    
    for prod in products:
        if prod in filename.split('_')[1]:
            file_type = prod

    year = timestamp[1:5]
    day_of_the_year = timestamp[5:8]
    time_of_day = timestamp[8:10]
    final_url = base_url + file_type + '/' + year + '/' + day_of_the_year + '/' + time_of_day + '/' + filename

    try:
        # Make a GET request to the URL
        response = requests.get(final_url)

        # Check if the response was successful
        if response.status_code == 200:
            write_logs("File url: "+ final_url +" downloaded")
            write_logs("Get file url function complete")
            data = {'message': final_url,'status_code': '200'}
            return data
        else:
            write_logs("File name not found")
            write_logs("Get file url function complete")
            data = {'message': 'File name not found','status_code': '404'}
            return data

    except Exception as e:
        write_logs("Get file url function throws error")
        write_logs("Get file url function complete")
        data = {'message': 'An error occured while retriving the file','status_code': '500'}
        return data
@app.get('/is_logged_in')
async def is_logged_in(getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    return {'status_code': '200'}




@app.post('/create_user')
async def create_default_user(user: schema.User):
    database_file_name = "assignment_01.db"
    database_file_path = os.path.join(project_dir, os.path.join('data/',database_file_name))
    db = sqlite3.connect(database_file_path)
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE if not exists Users (username,hashed_password,service_plan,api_limit)''')
    userExist= pd.read_sql_query('SELECT * FROM Users where username="{}"'.format(user.username), db)
    if len(userExist) == 0:
        pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_cxt.hash(user.hashed_password)
        cursor.execute("Insert into Users values (?,?,?,?)", (user.username,hashed_password,user.service_plan,user.api_limit))

    user= pd.read_sql_query("SELECT * FROM Users", db)
    if len(user) == 0:
        pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_cxt.hash(("spring2023"))
        cursor.execute("Insert into Users values (?,?,?,?)", ("user1",hashed_password,"Free",10))
        cursor.execute("Insert into Users values (?,?,?,?)", ("user2",hashed_password,"Gold",15))
        cursor.execute("Insert into Users values (?,?,?,?)", ("user3",hashed_password,"Platinum",20))
        db.commit()
        db.close()
    return {'status_code': '200'}




@app.post('/update_login')
async def login_update(getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    database_file_name = "assignment_01.db"
    database_file_path = os.path.join(project_dir, os.path.join('data/',database_file_name))
    db = sqlite3.connect(database_file_path)
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE if not exists Logins (username,logindate)''')
    cursor.execute("Insert into Logins values (?,?)", (getCurrentUser.username,datetime.utcnow()))
    db.commit()
    db.close()
    return {'status_code': '200'}

@app.post('/user_api_status')
async def get_user_data(api_details: schema.api_detail_fetch,getCurrentUser: schema.TokenData = Depends(oauth2.get_current_user)):
    database_file_name = "assignment_01.db"
    database_file_path = os.path.join('data/',database_file_name)
    db = sqlite3.connect(os.path.join(project_dir, database_file_path))
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE if not exists user_activity (username,api_limit,date,api_name,hit_count)''')
    cursor.execute('SELECT * FROM user_activity WHERE username =? ORDER BY date DESC LIMIT 1',(getCurrentUser.username,))
    result = cursor.fetchone()
    username=getCurrentUser.username
    api_limit=pd.read_sql_query('Select api_limit from Users where username="{}"'.format(username),db).api_limit.item()
    date = datetime.utcnow()
    api_name=api_details.api_name 
    if not result:
        hit_count = 1
        cursor.execute('INSERT INTO user_activity VALUES (?,?,?,?,?)', (username,api_limit,date,api_name,hit_count))
        db.commit()
    else:
        last_date = datetime.strptime(result[2], '%Y-%m-%d %H:%M:%S.%f')
        time_diff = datetime.utcnow() - last_date
        if time_diff <= timedelta(hours=1):
            if result[4]<api_limit:
                hit_count = result[4] + 1
                cursor.execute('INSERT INTO user_activity VALUES (?,?,?,?,?)', (username,api_limit,date,api_name,hit_count))
                db.commit()
            else:
                db.commit()
                db.close() 
                return Response(status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            hit_count = 1
            cursor.execute('INSERT INTO user_activity VALUES (?,?,?,?,?)', (username,api_limit,date,api_name,hit_count))
            db.commit()



@app.post("/signup")
async def signup(user_data: schema.User):
    database_file_name = "assignment_01.db"
    database_file_path = os.path.join(project_dir, os.path.join('data/',database_file_name))
    db = sqlite3.connect(database_file_path)
    cursor = db.cursor()
    pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_cxt.hash((user_data.password))
    cursor.execute("Insert into Users values (?,?,?,?)",
                   (user_data.username, hashed_password, user_data.service_plan, user_data.api_limit))
    db.commit()
    db.close()
    return {'df_dict':df_dict, 'status_code': '200'}

@app.get('/api_data')
async def api_data():
    database_file_name = "assignment_01.db"
    database_file_path = os.path.join('data/',database_file_name)
    db = sqlite3.connect(database_file_path)
    cursor = db.cursor()
    cursor.execute('''DROP TABLE if exists User_Activity_Data''')
    cursor.execute('''CREATE TABLE if not exists User_Activity_Data (username,service_plan,api_limit,date,time,api_name,request_status,hit_count)''')
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-01","12:11:07","goes_station","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-01","12:13:43","goes_years","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-01","12:14:31","goes_days","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-01","14:17:39","goes_hours","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-02","08:29:40","goes_files","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-02","08:29:49","goes_fetch_url","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-02","09:40:57","goes_AWS_url","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user1","free",10,"2023-02-03","00:18:33","validatefileUrl","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-03","22:55:21","getfileurl","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-03","21:32:06","nexrad_s3_fetch_db","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-03","09:47:54","nexrad_s3_fetch_month","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-03","09:38:58","nexrad_s3_fetch_day","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-03","02:37:35","nexrad_s3_fetch_station","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-04","18:22:25","nexrad_s3_fetch_file","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-04","21:37:21","nexrad_s3_fetchurl","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-04","05:10:35","nexrad_s3_fetch_key","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-02-04","13:39:14","nexrad_s3_upload","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-04","19:17:29","nexrad_s3_generate_user_link","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-05","06:21:05","create_plot_data","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-05","13:14:13","retrieve_plot_data","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-05","16:58:15","goes_station","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-05","15:29:04","goes_years","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-05","21:58:42","goes_days","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-05","01:32:26","goes_hours","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user2","gold",15,"2023-03-05","15:18:50","goes_files","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",20,"2023-03-08","08:23:36","goes_fetch_url","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",20,"2023-03-08","05:57:25","goes_AWS_url","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",20,"2023-03-08","08:50:59","validatefileUrl","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",20,"2023-03-08","10:26:56","getfileUrl","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",20,"2023-03-08","01:50:16","nexrad_s3_fetch_db","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",20,"2023-03-08","16:44:30","nexrad_s3_fetch_month","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",20,"2023-03-08","01:44:56","nexrad_s3_fetch_day","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user3","platinum",10,"2023-03-10","09:23:44","nexrad_s3_fetch_station","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-10","19:50:28","nexrad_s3_fetch_file","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-10","18:28:54","nexrad_s3_fetchurl","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-10","10:18:57","nexrad_s3_fetch_key","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-10","19:15:37","nexrad_s3_upload","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-10","10:19:20","nexrad_s3_generate_user_link","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-10","00:07:40","create_plot_data","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-10","21:30:33","retrieve_plot_data","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-11","06:34:14","retrieve_plot_data","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-11","03:25:59","goes_station","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-11","09:18:46","goes_years","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-11","08:36:55","goes_days","Success",1))
    cursor.execute("Insert into User_Activity_Data values (?,?,?,?,?,?,?,?)", ("user4","free",10,"2023-03-11","08:32:01","goes_hours","Success",1))
    db.commit()
    db.close()
    print("Data Inserted Successfully")
    return {'status_code': '200'}

@app.get('/getAnalyticsData')
async def get_analytics_data():
    database_file_name = "assignment_01.db"
    database_file_path = os.path.join('data/',database_file_name)
    db = sqlite3.connect(database_file_path)
    df = pd.read_sql_query("SELECT * FROM User_Activity_Data", db)
    df_dict = df.to_dict(orient='records')
    db.close()
    return {'df_dict':df_dict, 'status_code': '200'}

@app.get('/getUsersData')
async def get_analytics_data():
    database_file_name = "assignment_01.db"
    database_file_path = os.path.join('data/',database_file_name)
    db = sqlite3.connect(database_file_path)
    df = pd.read_sql_query("SELECT * FROM Users", db)
    df_dict = df.to_dict(orient='records')
    db.close()
    return {'df_dict':df_dict, 'status_code': '200'}
    
