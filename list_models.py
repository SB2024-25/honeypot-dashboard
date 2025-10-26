import os
import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()  # Loads variables from .env file into environment


def list_models():
    api_key = os.getenv("GOOGLE_API_KEY")  # Make sure your .env or env var has this set
    if not api_key:
        print("GOOGLE_API_KEY not found in environment variables.")
        return

    genai.configure(api_key=api_key)

    try:
        models = genai.list_models()
        print("Available Google Generative AI models:")
        for model in models:
            print(f"- {model.name}")
    except Exception as e:
        print(f"Error listing models: {e}")

if __name__ == "__main__":
    list_models()
