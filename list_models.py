import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load the API key from your .env file
load_dotenv()
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    print("API Key configured. Listing models...\n")

    try:
        # Iterate through the available models
        for m in genai.list_models():
            # Check if the model supports the 'generateContent' method we need
            if 'generateContent' in m.supported_generation_methods:
                print(f"Model Name: {m.name}")
                # print(f"  Supported Methods: {m.supported_generation_methods}")
                # print(f"  Description: {m.description}\n")
        print("\nFinished listing models.")

    except Exception as e:
        print(f"!!! An error occurred while listing models: {e}")
        print("!!! Please double-check your API key and network connection.")

else:
    print("!!! ERROR: GOOGLE_API_KEY not found in your .env file.")
    print("!!! Please make sure the .env file exists in the same directory and contains the key.")