# app/models.py
from django.db import models
from django.contrib.postgres.fields import ArrayField

class GoalChoices(models.TextChoices):
    DISCOVER_STYLE = "discoverStyle", "discoverStyle"
    FEEL_CONFIDENT = "feelConfident", "feelConfident"
    LOOK_ATTRACTIVE = "lookAttractive", "lookAttractive"
    SPEND_LESS = "spendLess", "spendLess"
    SAVE_TIME = "saveTime", "saveTime"
    OTHER = "other", "other"

class TrinaryChoices(models.TextChoices):
    YES = "yes", "yes"
    NO = "no", "no"
    PARTIALLY = "partially", "partially"

class WardrobeChoices(models.TextChoices):
    P10 = "10%", "10%"
    P25 = "25%", "25%"
    P50 = "50%", "50%"
    P75 = "75%", "75%"
    P90 = "90%+", "90%+"

class WastedResourcesChoices(models.TextChoices):
    ALL = "allTimes", "allTimes"
    OFTEN = "oftenTimes", "oftenTimes"
    FEW = "fewTimes", "fewTimes"
    NEVER = "never", "never"

class FeelingSecureChoices(models.TextChoices):
    YES = "yes", "yes"
    NO = "no", "no"
    NOT_SURE = "notSure", "notSure"

class FeelingAnxiousChoices(models.TextChoices):
    STRUGGLE = "struggle", "struggle"
    DEPENDS = "depends", "depends"
    RARELY = "rarely", "rarely"
    NO = "no", "no"

class AgesChoices(models.TextChoices):
    A18_29 = "18-29", "18-29"
    A30_39 = "30-39", "30-39"
    A40_49 = "40-49", "40-49"
    A50P = "50+", "50+"

class GendersChoices(models.TextChoices):
    MALE = "male", "male"
    FEMALE = "female", "female"
    OTHER = "other", "other"

class HeightUnitChoices(models.TextChoices):
    CM = "cm", "cm"
    INCH = "inch", "inch"

class WeightUnitChoices(models.TextChoices):
    LB = "lb", "lb"
    KG = "kg", "kg"

class BodyShapesChoices(models.TextChoices):
    HOURGLASS = "hourglass", "hourglass"
    BOTTOM_HOURGLASS = "bottomHourglass", "bottomHourglass"
    TOP_HOURGLASS = "topHourglass", "topHourglass"
    SPOON = "spoon", "spoon"
    INV_TRI = "invertedTriangle", "invertedTriangle"
    TRIANGLE = "triangle", "triangle"
    RECTANGLE = "rectangle", "rectangle"

class EyeColorsChoices(models.TextChoices):
    BRIGHT_BLUE = "brightBlue", "brightBlue"
    LIGHT_BLUE = "lightBlue", "lightBlue"
    BRIGHT_GREEN = "brightGreen", "brightGreen"
    LIGHT_GREEN = "lightGreen", "lightGreen"
    GRAY = "gray", "gray"
    AMBER = "amber", "amber"
    LIGHT_HAZEL = "lightHazel", "lightHazel"
    DARK_HAZEL = "darkHazel", "darkHazel"
    LIGHT_BROWN = "lightBrown", "lightBrown"
    DARK_BROWN = "darkBrown", "darkBrown"
    MUTED_BROWN = "mutedBrown", "mutedBrown"
    BLACK = "black", "black"

class HairColorsChoices(models.TextChoices):
    ASH_BLONDE = "ashBlonde", "ashBlonde"
    GOLDEN_BLONDE = "goldenBlonde", "goldenBlonde"
    ASH_BROWN = "ashBrown", "ashBrown"
    COOL_BROWN = "coolBrown", "coolBrown"
    BROWN = "brown", "brown"
    WARM_BROWN = "warmBrown", "warmBrown"
    STRAWBERRY_BLONDE = "strawberryBlonde", "strawberryBlonde"
    COPPER = "copper", "copper"
    AUBURN = "auburn", "auburn"
    DARK_AUBURN = "darkAuburn", "darkAuburn"
    BROWN_BLACK = "brownBlack", "brownBlack"
    BLACK = "black", "black"

class SkinTonesChoices(models.TextChoices):
    COOL_PALE = "coolPale", "coolPale"
    PORCELAIN = "porcelain", "porcelain"
    IVORY = "ivory", "ivory"
    PEACH = "peach", "peach"
    ROSY_BEIGE = "rosyBeige", "rosyBeige"
    NEUTRAL_BEIGE = "neutralBeige", "neutralBeige"
    GOLDEN_BEIGE = "goldenBeige", "goldenBeige"
    OLIVE = "olive", "olive"
    TAN = "tan", "tan"
    BRONZE = "bronze", "bronze"
    CHOCOLATE = "chocolate", "chocolate"
    ESPRESSO = "espresso", "espresso"

class AestheticStylesChoices(models.TextChoices):
    CASUAL = "casual", "casual"
    GLAM = "glam", "glam"
    BOHO = "boho", "boho"
    ROMANTIC = "romantic", "romantic"
    MINIMALIST = "minimalist", "minimalist"
    CLASSIC = "classic", "classic"
    STREET = "street", "street"
    PREPPY = "preppy", "preppy"
    EDGY = "edgy", "edgy"
    SPORTY = "sporty", "sporty"
    Y2K = "Y2K", "Y2K"
    ECLECTIC = "eclectic", "eclectic"

class UserStyleProfile(models.Model):
    class Meta:
        db_table = "user_style_profiles"
        indexes = [models.Index(fields=["kratos_identity_id"])]

    kratos_identity_id = models.CharField(max_length=64, unique=True)

    # required
    wastedResources = models.CharField(max_length=20, choices=WastedResourcesChoices.choices)
    feelingSecure = models.CharField(max_length=20, choices=FeelingSecureChoices.choices)
    feelingAnxious = models.CharField(max_length=20, choices=FeelingAnxiousChoices.choices)
    ages = models.CharField(max_length=10, choices=AgesChoices.choices)
    genders = models.CharField(max_length=10, choices=GendersChoices.choices)
    heightUnit = models.CharField(max_length=10, choices=HeightUnitChoices.choices)
    weightUnit = models.CharField(max_length=10, choices=WeightUnitChoices.choices)
    bodyShapes = models.CharField(max_length=30, choices=BodyShapesChoices.choices)
    eyeColors = models.CharField(max_length=20, choices=EyeColorsChoices.choices)
    hairColors = models.CharField(max_length=20, choices=HairColorsChoices.choices)
    skinTones = models.CharField(max_length=20, choices=SkinTonesChoices.choices)
    aestheticStyles = models.CharField(max_length=20, choices=AestheticStylesChoices.choices)

    # optional
    goals = ArrayField(
        base_field=models.CharField(max_length=32, choices=GoalChoices.choices),
        default=list,
        blank=True,
    )
    knowingStyles = models.CharField(max_length=20, choices=TrinaryChoices.choices, null=True, blank=True)
    feelingConfident = models.CharField(max_length=20, choices=TrinaryChoices.choices, null=True, blank=True)
    wardrobeWeared = models.CharField(max_length=10, choices=WardrobeChoices.choices, null=True, blank=True)

    # timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def to_dict(self):
        return {
            "id": self.pk,
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
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
