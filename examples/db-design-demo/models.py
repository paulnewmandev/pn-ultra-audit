from django.db import models
class Customer(models.Model):
    email = models.EmailField()
    signup_date = models.CharField(max_length=20)
class Order(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    total = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)
