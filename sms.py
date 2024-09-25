from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from twilio.rest import Client

# Initialize FastAPI app
app = FastAPI()

# Twilio credentials (replace these with your own Twilio credentials)
account_sid = "TWILIO_ACCOUNT_SID"
auth_token = "TWILIO_AUTH_TOKEN"
twilio_phone_number = "TWILIO_phone_number"  # Your Twilio phone number

# Twilio client
client = Client(account_sid, auth_token)

# Pydantic schema for request body
class SMSRequest(BaseModel):
    phone_number: str  # Regex to validate phone number format
    message: str

# POST method to send SMS
@app.post("/send_sms/")
async def send_sms(sms: SMSRequest):
    try:
        # Send SMS via Twilio
        message = client.messages.create(
            body=sms.message,
            from_=twilio_phone_number,
            to=sms.phone_number
        )
        
        return {"message": "SMS sent successfully", "sid": message.sid}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error sending SMS: {str(e)}")