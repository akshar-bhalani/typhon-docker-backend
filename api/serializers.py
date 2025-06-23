from datetime import datetime
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import ValidationError


from api.models import Blog, BlogSetting, Category, Feature, Payment, SocialMedia, SubCategory, SubscriptionPlan, UserGeneratedTopic, UserParameter, WordPress,Review,CustomBlogTopic

User = get_user_model()

class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = (
            'email', 
            'name', 
            'password', 
            'confirm_password', 
            'company_name', 
            'phone',
            'role'
        )
        extra_kwargs = {
            'role': {'required': False}
        }

    def validate(self, attrs):
        # Check if passwords match
        if attrs['password'] != attrs.pop('confirm_password'):
            raise ValidationError({"password": "Password fields didn't match."})
        
        # Check if email already exists
        if User.objects.filter(email=attrs['email']).exists():
            raise ValidationError({"email": "A user with this email already exists."})
        
        return attrs

    def create(self, validated_data):
        # Set default role to 'User' if not provided
        validated_data['role'] = validated_data.get('role', 'User')
        
        # Create user
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            name=validated_data.get('name'),
            company_name=validated_data.get('company_name'),
            phone=validated_data.get('phone'),
            role=validated_data['role']
        )
        
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class SubCategorySerializer(serializers.ModelSerializer):
    """
    Serializer for SubCategory model.
    """
    class Meta:
        model = SubCategory
        fields = ['id', 'name', 'category']
        read_only_fields = ['category']  # Prevent category from being modified in subcategory updates


class CategorySerializer(serializers.ModelSerializer):
    """
    Serializer for Category model.
    Includes nested subcategories.
    """
    subcategories = SubCategorySerializer(many=True, read_only=True)

    class Meta:
        model = Category
        fields = ['id', 'name', 'subcategories']

        
class UserParameterSerializer(serializers.ModelSerializer):
    subcategories = SubCategorySerializer(many=True, read_only=True)  # Use nested serializer for subcategories

    class Meta:
        model = UserParameter
        fields = ['number_of_posts', 'word_count', 'subcategories']



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','name','role','email','company_name','phone','status','assigned_admin']

class FeatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feature
        fields = ['name', 'is_enabled']

        
class BlogSettingSerializer(serializers.ModelSerializer):
    wordpress_username=serializers.SerializerMethodField()
    class Meta:
        model = BlogSetting
        fields = [
            'id',
            'name',
            'frequency_value',
            'cycle_interval',
            'created_at',
            'updated_at',
            'wordpress_id',
            'wordpress_username',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_wordpress_username(self, obj):
        return obj.wordpress_id.wordpress_username if obj.wordpress_id else None


    def create(self, validated_data):
        """
        Custom create method to ensure the user_id is set correctly.
        """
        user = self.context['request'].user
        validated_data['user_id'] = user  # Pass user directly (not user_id)
        return BlogSetting.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """
        Custom update method to ensure 'user_id' is not updated.
        """
        validated_data.pop('user_id', None)  # Prevent updating user_id
        return super().update(instance, validated_data)
    


class SocialMediaSerializer(serializers.ModelSerializer):
    username = serializers.ReadOnlyField(source='user_id.name')
    platform_display = serializers.ReadOnlyField(source='get_platform_display')
    
    class Meta:
        model = SocialMedia
        fields = [
            'id', 'user_id', 'username', 'platform', 'platform_display', 
            'title', 'link', 'publish_date', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'username', 'platform_display']
    
    def create(self, validated_data):
        # Set the user to the current authenticated user if not provided
        if 'user_id' not in validated_data:
            validated_data['user_id'] = self.context['request'].user
        return super().create(validated_data)


class WordPressSerializer(serializers.ModelSerializer):
    class Meta:
        model = WordPress
        fields = ['id', 'wordpress_username','wordpress_key_name', 'wordpress_api_key', 'wordpress_url','wordpress_uuid']
        read_only_fields = ['id']

    def create(self, validated_data):
        """
        Custom create method to ensure the user_id is set correctly.
        """
        user = self.context['request'].user
        validated_data['user_id'] = user  # Automatically assign the user
        return WordPress.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """
        Custom update method to ensure 'user_id' is not updated.
        """
        validated_data.pop('user_id', None)  # Prevent updating user_id
        return super().update(instance, validated_data)
    

class CustomUserSerializer(serializers.ModelSerializer):
    user_parameters = UserParameterSerializer(source="parameters", many=False, read_only=True)
    wordpress_accounts = WordPressSerializer(many=True, read_only=True)
      
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'user_parameters',
            'wordpress_accounts',
        ]
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        user_parameters = representation.pop('user_parameters', None)
        wordpress_accounts = representation.pop('wordpress_accounts', [])
        
        # If user_parameters exists, add them to the main representation
        if user_parameters:
            representation.update({
                'number_of_posts': user_parameters['number_of_posts'],
                'word_count': user_parameters['word_count'],
                'subcategories': user_parameters['subcategories']
            })
        
        # Merge first WordPress account if it exists
        if wordpress_accounts:
            wordpress = wordpress_accounts[0]
            representation.update({
                'wordpress_id': wordpress['id'],
                'wordpress_username': wordpress['wordpress_username'],
                'wordpress_api_key': wordpress['wordpress_api_key'],
                'wordpress_url': wordpress['wordpress_url']
            })

            blog_setting = BlogSetting.objects.filter(
                    user_id=instance.id,
                    wordpress_id=wordpress['id']
            ).first()
            if blog_setting:
                representation['setting_id'] = blog_setting.id
        
        return representation


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """
    Serializer for the SubscriptionPlan model.
    """
    price_id = serializers.CharField(read_only=True)
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id',
            'name',
            'description',
            'price_per_month',
            'currency',
            'price_id',  # Stripe price ID
            'max_blogs_per_month',
            'max_refresh_count',
            'frequency',
            'created_at',
            'updated_at',
        ]

class UserParameterSerializer(serializers.ModelSerializer):
    categories = serializers.SerializerMethodField()
    class Meta:
        model = UserParameter
        fields = [
            'id',
            'user',
            'number_of_posts',
            'word_count',
            'subcategories',
            'categories',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id','created_at', 'updated_at']

    def get_categories(self, obj):
        """
        Retrieve the unique category IDs associated with the subcategories.
        """
        categories = Category.objects.filter(subcategories__in=obj.subcategories.all()).distinct()
        return categories.values_list('id', flat=True)

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = [
            'id',
            'user_id',
            'amount',
            'currency',
            'payment_date',
            'payment_method',
            'plan_id',
            'payment_status',
        ]
        read_only_fields = ['id', 'user_id']

    def create(self, validated_data):
        validated_data['user_id'] = self.context['request'].user
        return Payment.objects.create(**validated_data)


class BlogSerializer(serializers.ModelSerializer):
    wordpress_username=serializers.SerializerMethodField()
    class Meta:
        model = Blog
        fields = [
            'id',
            'title',
            'link',
            'wordpress_key',
            'wordpress_username',
            'publish_date',
            'updated_at',
            'refresh_count',
            'setting_id',
            'user_id'
        ]
        read_only_fields = ['id', 'updated_at', 'refresh_count']

    def get_wordpress_username(self, obj):
        # Ensure the related objects exist before accessing fields
        if obj.setting_id and obj.setting_id.wordpress_id:
            return obj.setting_id.wordpress_id.wordpress_username  # Replace 'user_name' with the actual field name
        return None


class OnlyCategorySerializer(serializers.ModelSerializer):
    """
    Serializer for Category model.
    Includes nested subcategories.
    """
  

    class Meta:
        model = Category
        fields = ['id', 'name']

class CustomBlogTopicSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomBlogTopic
        fields = [
            'id',
            'user',
            'title',
            'usage_date',
            'primary_keyword',
            'secondary_keyword',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def validate_primary_keyword(self, value):
        """
        Validate that primary keyword is not empty
        """
        if not value.strip():
            raise serializers.ValidationError("Primary keyword cannot be empty")
        return value.strip()

    def validate_usage_date(self, value):
        """
        Validate that usage_date is in the correct format
        """
        try:
            datetime.strptime(str(value), '%Y-%m-%d')
            return value
        except ValueError:
            raise serializers.ValidationError("Date must be in YYYY-MM-DD format")
    
class UserGeneratedTopicSerializer(serializers.ModelSerializer):
    # category = OnlyCategorySerializer( read_only=True)
    # subcategories = SubCategorySerializer(many=True, read_only=True)

    class Meta:
        model = UserGeneratedTopic
        fields = ['id', 'user', 'title', 'date', 'created_at', 'updated_at']
        


class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = '__all__'