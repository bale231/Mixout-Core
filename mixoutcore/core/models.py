# app/models.py
from datetime import datetime
from mongoengine import (
    Document, StringField, ListField, DateTimeField
)
from mongoengine.errors import ValidationError

GOAL_CHOICES = (
    'discoverStyle', 'feelConfident', 'lookAttractive',
    'spendLess', 'saveTime', 'other'
)

TRINARY_CHOICES = ('yes', 'no', 'partially')

WARDROBE_CHOICES = ('10%', '25%', '50%', '75%', '90%+')

WASTED_RESOURCES_CHOICES = ('allTimes', 'oftenTimes', 'fewTimes', 'never')
FEELING_SECURE_CHOICES = ('yes', 'no', 'notSure')
FEELING_ANXIOUS_CHOICES = ('struggle', 'depends', 'rarely', 'no')

AGES_CHOICES = ('18-29', '30-39', '40-49', '50+')
GENDERS_CHOICES = ('male', 'female', 'other')

HEIGHT_UNIT_CHOICES = ('cm', 'inch')
WEIGHT_UNIT_CHOICES = ('lb', 'kg')

BODY_SHAPES_CHOICES = (
    'hourglass', 'bottomHourglass', 'topHourglass', 'spoon',
    'invertedTriangle', 'triangle', 'rectangle'
)

EYE_COLORS_CHOICES = (
    'brightBlue', 'lightBlue', 'brightGreen', 'lightGreen', 'gray',
    'amber', 'lightHazel', 'darkHazel', 'lightBrown', 'darkBrown',
    'mutedBrown', 'black'
)

HAIR_COLORS_CHOICES = (
    'ashBlonde', 'goldenBlonde', 'ashBrown', 'coolBrown', 'brown',
    'warmBrown', 'strawberryBlonde', 'copper', 'auburn', 'darkAuburn',
    'brownBlack', 'black'
)

SKIN_TONES_CHOICES = (
    'coolPale', 'porcelain', 'ivory', 'peach', 'rosyBeige',
    'neutralBeige', 'goldenBeige', 'olive', 'tan', 'bronze',
    'chocolate', 'espresso'
)

AESTHETIC_STYLES_CHOICES = (
    'casual', 'glam', 'boho', 'romantic', 'minimalist', 'classic',
    'street', 'preppy', 'edgy', 'sporty', 'Y2K', 'eclectic'
)


class UserStyleProfile(Document):
    meta = {
        'collection': 'user_style_profiles',
        'indexes': ['kratos_identity_id'],
    }

    # Identity di Ory Kratos (UUID) - chiave logica unica
    kratos_identity_id = StringField(required=True, unique=True)

    # Campi richiesti/obbligatori
    wastedResources = StringField(choices=WASTED_RESOURCES_CHOICES, required=True)
    feelingSecure = StringField(choices=FEELING_SECURE_CHOICES, required=True)
    feelingAnxious = StringField(choices=FEELING_ANXIOUS_CHOICES, required=True)
    ages = StringField(choices=AGES_CHOICES, required=True)
    genders = StringField(choices=GENDERS_CHOICES, required=True)
    heightUnit = StringField(choices=HEIGHT_UNIT_CHOICES, required=True)
    weightUnit = StringField(choices=WEIGHT_UNIT_CHOICES, required=True)
    bodyShapes = StringField(choices=BODY_SHAPES_CHOICES, required=True)
    eyeColors = StringField(choices=EYE_COLORS_CHOICES, required=True)
    hairColors = StringField(choices=HAIR_COLORS_CHOICES, required=True)
    skinTones = StringField(choices=SKIN_TONES_CHOICES, required=True)
    aestheticStyles = StringField(choices=AESTHETIC_STYLES_CHOICES, required=True)

    # Campi opzionali (possono essere null)
    goals = ListField(StringField(choices=GOAL_CHOICES), default=list)
    knowingStyles = StringField(choices=TRINARY_CHOICES, null=True, default=None)
    feelingConfident = StringField(choices=TRINARY_CHOICES, null=True, default=None)
    wardrobeWeared = StringField(choices=WARDROBE_CHOICES, null=True, default=None)

    # Timestamps
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    def clean(self):
        # aggiorna updated_at ad ogni save/validate
        self.updated_at = datetime.utcnow()

    def to_dict(self):
        return {
            "id": str(self.id), # type: ignore
            "kratos_identity_id": self.kratos_identity_id,
            "goals": self.goals,
            "knowingStyles": self.knowingStyles,
            "feelingConfident": self.feelingConfident,
            "wardrobeWeared": self.wardrobeWeared,
            "wastedResources": self.wastedResources,
            "feelingSecure": self.feelingSecure,
            "feelingAnxious": self.feelingAnxious,
            "ages": self.ages,
            "genders": self.genders,
            "heightUnit": self.heightUnit,
            "weightUnit": self.weightUnit,
            "bodyShapes": self.bodyShapes,
            "eyeColors": self.eyeColors,
            "hairColors": self.hairColors,
            "skinTones": self.skinTones,
            "aestheticStyles": self.aestheticStyles,
            "created_at": self.created_at.isoformat(), # type: ignore
            "updated_at": self.updated_at.isoformat(), # type: ignore
        }
