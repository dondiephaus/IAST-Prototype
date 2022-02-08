from app import app
from app.config import Config

# Run app with Config values
app.config.from_object(Config)
app.run(port=Config.PORT, debug=Config.DEBUG)



