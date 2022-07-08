#!/bin/bash

# Migrate db changes
python manage.py makemigrations
python manage.py migrate --no-input

# load database files
python manage.py load_db_files

# Start the server
python manage.py runserver 0.0.0.0:8000
