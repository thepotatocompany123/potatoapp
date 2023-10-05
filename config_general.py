import os
from secrets import token_hex
from selenium.webdriver.firefox.options import Options

class AppConfig:
    SECRET_KEY = 'this_is_super_secure_secret_key'
    SESSION_TYPE = 'filesystem'
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'potatoes.db')

    # Selenium configuration
    DRIVER_PATH = "/app/geckodriver"
    SELENIUM_OPTIONS = Options()
    SELENIUM_OPTIONS.add_argument('--headless')

# Always set DEBUG to False
DEBUG = False

# Choose the configuration class based on your environment
config = AppConfig
