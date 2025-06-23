from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone
import bcrypt
from django.contrib.auth.models import AbstractUser
from django.db.models import Q
import uuid
import os

from dotenv import load_dotenv

load_dotenv()
# Users Table
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        extra_fields['username'] = email  # Explicitly set username
        
        user = self.model(email=email, **extra_fields)
        
        # Use bcrypt for password hashing
        if password:
            user.set_password(password)
        
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create a superuser with admin privileges
        """
        extra_fields.setdefault('role', 'Admin')
        
        user = self.create_user(email, password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

    def get_users_for_role(self, user):
        """Return filtered users based on role."""
        if user.role == 'SuperAdmin':
            return self.filter(is_deleted=False)
        if user.role == 'Admin':
            return self.filter(Q(id=user.id) | Q(assigned_admin=user), is_deleted=False)
        elif user.role == 'User':
            return self.filter(id=user.id, is_deleted=False)
        return self.none()

class User(AbstractUser):
    name = models.CharField(max_length=255, null=True, blank=True)
    company_name = models.CharField(max_length=255, null=True, blank=True)

    # Predefined role choices
    ROLE_CHOICES = [
        ('SuperAdmin', 'Super Administrator'),
        ('Admin', 'Administrator'),
        ('User', 'Regular User'),
    ]
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='User')
    
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended')
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='active')

    stripe_customer_id = models.CharField(max_length=255, null=True, blank=True)
    subscription_id = models.CharField(max_length=255, blank=True, null=True)
    subscription_status = models.CharField(max_length=50, default='inactive') 

    assigned_admin = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, limit_choices_to={'role': 'Admin'})
    
    
    # Fields to make it compatible with Django's authentication system
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    is_deleted = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
    
    def soft_delete(self):
        """Mark the user as deleted instead of actually deleting."""
        self.is_deleted = True
        self.save()

    def __str__(self):
        return self.email
    
    class Meta:
        ordering = ['id'] 

# models.py


class Feature(models.Model):
    name = models.CharField(max_length=100)
    is_enabled = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class WordPress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="wordpress_accounts")
    wordpress_username = models.CharField(max_length=255)  # Stores the WordPress username
    wordpress_key_name=models.CharField(max_length=255,null=True,blank=True) 
    wordpress_api_key = models.TextField()
    wordpress_url = models.URLField()   
    wordpress_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True,null=True,blank=True)              # Stores the WordPress site URL
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        ordering = ['id'] 

    def soft_delete(self):
        """Soft delete the subscription plan."""
        self.is_deleted = True
        self.save()

    def __str__(self):
        return f"WordPress account for {self.user.username} ({self.wordpress_url})"
    
   

# Subscription Plans Table
class SubscriptionPlan(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    price_per_month = models.DecimalField(max_digits=10, decimal_places=2)
    max_blogs_per_month = models.IntegerField()
    max_refresh_count = models.IntegerField()
    frequency = models.CharField(max_length=50)  # e.g., daily, weekly
    price_id = models.CharField(max_length=255, unique=True)  # Stripe price ID
    product_id = models.CharField(max_length=255, unique=True)
    currency = models.CharField(max_length=10, default="usd")  # Currency of the plan
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        ordering = ['id'] 
    
    def soft_delete(self):
        """Soft delete the subscription plan."""
        self.is_deleted = True
        self.save()

    def restore(self):
        """Restore a soft-deleted subscription plan."""
        self.is_deleted = False
        self.save()


# User Subscriptions Table
class UserSubscription(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    plan_id = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    status = models.CharField(max_length=50, default='active')

# Payments Table
class Payment(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)  # Assuming a User model exists
    plan = models.ForeignKey('SubscriptionPlan', on_delete=models.CASCADE)  # Subscription Plan details
    stripe_payment_id = models.CharField(max_length=256, blank=True)  # Right now we are using session checkout of stripe so its dont have payment id so we are using session id to keep unique payment record
    stripe_invoice_id = models.CharField(max_length=64, blank=True, unique=True)  # Stripe Invoice ID
    stripe_subscription_id = models.CharField(max_length=64, blank=True)  # Stripe Subscription ID
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)  # Payment amount
    currency = models.CharField(max_length=10, default="USD")
    payment_method = models.CharField(max_length=50, blank=True)  # e.g., Stripe, Credit Card
    payment_status = models.CharField(max_length=50, default='completed')  # Payment status
    payment_date = models.DateTimeField(auto_now_add=True)  # DateTime of payment
    failure_reason = models.CharField(max_length=64, blank=True)  # Reason for payment failure (if any)

    

    def __str__(self):
        return f'Payment - {self.amount} {self.payment_status}'

# Blogs Table


# Blog Settings Table
class BlogSetting(models.Model):
    name = models.CharField(max_length=255)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    frequency_value = models.CharField(max_length=50)  # e.g., daily, weekly
    cycle_interval = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    wordpress_id = models.ForeignKey(WordPress, on_delete=models.SET_NULL, null=True, blank=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        ordering = ['id'] 

    def soft_delete(self):
        """Soft delete the subscription plan."""
        self.is_deleted = True
        self.save()


class Blog(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    link = models.TextField(null=True, blank=True)
    wordpress_key = models.IntegerField(default=0)
    publish_date = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)
    refresh_count = models.IntegerField(default=0)
    setting_id = models.ForeignKey(BlogSetting, on_delete=models.SET_NULL, null=True, blank=True)
    

class SocialMedia(models.Model):
    PLATFORM_CHOICES = [
        ('facebook', 'Facebook'),
        ('x', 'X'),
        ('instagram', 'Instagram'),
        ('linkedin', 'LinkedIn'),
        
    ]
    
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_media_posts')
    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
    title = models.CharField(max_length=255)
    link = models.URLField(max_length=500)
    publish_date = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-publish_date']
        verbose_name = 'Social Media Post'
        verbose_name_plural = 'Social Media Posts'
    
    def __str__(self):
        return f"{self.platform} - {self.title}"
    
class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class SubCategory(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name="subcategories")
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('category', 'name')

    def __str__(self):
        return f"{self.category.name} - {self.name}"
    
# User Parameters Table
class UserParameter(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="parameters")
    number_of_posts = models.PositiveIntegerField(default=0)  # Stores the number of posts
    word_count = models.PositiveIntegerField(default=0)       # Stores the word count
    subcategories = models.ManyToManyField(SubCategory, blank=True)                 # Stores categories as comma-separated values
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Parameters for {self.user.username}"

# User Settings Table
class UserSetting(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=False)
    push_notifications = models.BooleanField(default=True)
    newsletter_subscribed = models.BooleanField(default=True)
    blog_update_notifications = models.BooleanField(default=True)
    payment_notifications = models.BooleanField(default=True)
    system_alerts = models.BooleanField(default=True)
    notification_preference = models.CharField(max_length=50, default='email')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# User Activity Log Table
class UserActivityLog(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    details = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

# API Usage Table
class APIUsage(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    api_key = models.CharField(max_length=255)
    type = models.CharField(max_length=50)  # e.g., openApi, wordpress
    api_endpoint = models.CharField(max_length=255)
    request_count = models.IntegerField()
    last_request = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



# Feature Flags Table
class FeatureFlag(models.Model):
    feature_name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    is_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# Beta Access Table
class BetaAccess(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    feature_id = models.ForeignKey(FeatureFlag, on_delete=models.CASCADE)
    access_granted_at = models.DateTimeField()
    access_revoked_at = models.DateTimeField(null=True, blank=True)

# System Config Table
class SystemConfig(models.Model):
    config_key = models.CharField(max_length=255)
    config_value = models.TextField()
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# Third-Party Integrations Table
class ThirdPartyIntegration(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    service_name = models.CharField(max_length=255)
    api_key = models.CharField(max_length=255)
    integration_status = models.CharField(max_length=50, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Referral(models.Model):
    referral_id = models.UUIDField(primary_key=True, default=models.UUIDField, editable=False)
    referrer_user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='referrals_made')
    referred_user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='referrals_received')
    referral_code = models.CharField(max_length=255, unique=True)
    reward_status = models.CharField(max_length=50, default='pending')  # e.g., 'paid', 'pending'
    reward_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# Content Moderation Table
class ContentModeration(models.Model):
    moderation_id = models.UUIDField(primary_key=True, default=models.UUIDField, editable=False)
    blog_id = models.ForeignKey(Blog, on_delete=models.CASCADE)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=50)  # e.g., 'approved', 'pending', 'rejected'
    comments = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class CustomBlogTopic(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="custom_blog_topics")
    title = models.CharField(max_length=255)
    usage_date = models.DateField()
    primary_keyword = models.CharField(max_length=255)  # Required field
    secondary_keyword = models.CharField(max_length=255, null=True, blank=True)  # Optional field
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-usage_date']
        verbose_name = 'Custom Blog Topic'
        verbose_name_plural = 'Custom Blog Topics'

    def __str__(self):
        return f"{self.title} ({self.usage_date}) - {self.user.email}"

    def clean(self):
        from django.core.exceptions import ValidationError
        
        # Count existing topics for this date and user
        topics_count = CustomBlogTopic.objects.filter(
            usage_date=self.usage_date,
            user=self.user
        ).exclude(pk=self.pk).count()
        
        if topics_count >= 3:
            raise ValidationError(
                f"Maximum 3 topics are allowed per date. You already have {topics_count} topics for {self.usage_date}"
            )

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)



class UserGeneratedTopic(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="generated_topics")  # Associate topics with a user
    title = models.CharField(max_length=255)  # The generated topic title
    date = models.DateField()  # The date associated with the topic
    # category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name="user_generated_topics")  # The main category
    # subcategories = models.ManyToManyField(SubCategory, blank=True, related_name="user_generated_topics")  # Associated subcategories
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for when the topic was created
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp for when the topic was last updated

    def __str__(self):
        return f"{self.title} ({self.date}) - {self.user.email}"








class Review(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reviews")  # Associate reviews with a user
    name = models.CharField(max_length=255)  # Name of the reviewer
    number = models.CharField(max_length=20, null=True, blank=True)  # Phone number of the reviewer
    email = models.EmailField()  # Email of the reviewer
    review = models.TextField()  # Review content
    rating = models.PositiveIntegerField()  # Rating (e.g., 1-5)
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for when the review was created
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp for when the review was last updated

    def __str__(self):
        return f"Review by {self.name} - Rating: {self.rating}"