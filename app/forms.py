from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField
from wtforms.validators import URL, DataRequired

# WTForms implementation of the form of the IAST-Prototype dashboard
class StartScanForm(FlaskForm):
    # Validates if input matches URL RegEx, require_tld=False -> accept localhost:xxxx
    target = StringField('Target URL:', validators=[DataRequired(), URL(require_tld=False)])
    submit = SubmitField('Start Scan')