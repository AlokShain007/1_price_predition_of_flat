from django.db import models

class RealEstateListing(models.Model):
    bhk = models.IntegerField()
    bath = models.FloatField()  # Add the 'bath' field
    total_sqft = models.FloatField()
    price = models.FloatField()

    # def __str__(self):
    #     return f"{self.bhk} BHK, Total Sqft: {self.total_sqft}, Price: {self.price}"
