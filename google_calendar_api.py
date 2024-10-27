import os.path
from datetime import datetime, UTC
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Define the access scope for Google Calendar API
SCOPES = ["https://www.googleapis.com/auth/calendar"]


# Get Google Calendar API credentials
def get_credentials():
    creds = None
    if os.path.exists("credentials/token.json"):
        creds = Credentials.from_authorized_user_file("credentials/token.json")
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials/credentials.json", SCOPES)

            creds = flow.run_local_server(port=0)

    with open("credentials/token.json", "w") as token:
        token.write(creds.to_json())
    return creds


def create_task(service):
    # TUTAJ DODAJ ARGS
    try:
        task = {'action': 'TEMPLATE', 'summary': 'do laundry', 'colorId': 6, 'start', 'end'}

        # Insert the task into Google Calendar
        new_task = service.events().insert(calendarId='primary', body=task).execute()
        print(f'Event created: {new_task.get("htmlLink")}')
    except HttpError as error:
        print(f'An error occurred: {error}')


def main():
    # Get Google Calendar API credentials
    creds = get_credentials()
    # Build Google Calendar API service
    service = build("calendar", "v3", credentials=creds)

    # Create a Google Calendar event
    create_task(service)






    # Call the Calendar API
    now = datetime.now(UTC).isoformat()
    print("Getting the upcoming 10 events")
    events_result = (
        service.events()
        .list(
            calendarId="primary",
            timeMin=now,
            maxResults=10,
            singleEvents=True,
            orderBy="startTime",
        )
        .execute()
    )
    events = events_result.get("items", [])

    if not events:
        print("No upcoming events found.")
        return

    # Prints the start and name of the next 10 events
    for event in events:
        start = event["start"].get("dateTime", event["start"].get("date"))
        print(start, event["summary"])



if __name__ == "__main__":
    main()

# address:
# http: // www.google.com / calendar / event?
# This is the
# base
# of
# the
# address
# before
# the
# parameters
# below.
#
# action:
# action = TEMPLATE
# A
# default
# required
# parameter.
#
# src:
# Example: src = default % 40
# gmail.com
# Format: src = text
# This is not covered
# by
# Google
# help
# but is an
# optional
# parameter
# in order
# to
# add
# an
# event
# to
# a
# shared
# calendar
# rather
# than
# a
# user
# 's default.
#
# text:
# Example: text = Garden % 20
# Waste % 20
# Collection
# Format: text = text
# This is a
# required
# parameter
# giving
# the
# event
# title.
#
# dates:
# Example: dates = 20090621
# T063000Z / 20090621
# T080000Z
# (i.e.an event on 21 June 2009 from 7.30am to 9.0am
# British Summer Time (=GMT+1)).
# Format: dates = YYYYMMDDToHHMMSSZ / YYYYMMDDToHHMMSSZ
# This
# required
# parameter
# gives
# the
# start and end
# dates and times
# (in Greenwich Mean Time)
# for the event.
#
# location:
# Example: location = Home
# Format: location = text
# The
# obvious
# location
# field.
#
# trp:
# Example: trp = false
# Format: trp = true / false
# Show
# event as busy(true) or available(false)
#
# sprop:
# Example: sprop = http % 3
# A % 2
# F % 2
# Fwww.me.org
# Example: sprop = name:Home % 20
# Page
# Format: sprop = website and / or sprop = name:website_name
#
# add:
# Example: add = default % 40
# gmail.com
# Format: add = guest
# email
# addresses
#
# details: (extra)
# Example: details = Event % 20
# multiline % 0
# Adetails
# Format: details = description
# text(google
# also
# accepts
# html in this
# text)