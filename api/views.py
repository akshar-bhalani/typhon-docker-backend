
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status,permissions
from rest_framework.decorators import action,permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny,IsAuthenticated
import requests
from api.permissions import IsAdminOrSelf, IsAdminUser, IsSuperAdmin, IsAdminOrAssigned, IsSuperAdminOrAdmin, IsSuperAdminOrAdminOrAssigned, IsSuperAdminOrAdmin,WordPressPermission,BlogSettingPermission
from .models import Blog, BlogSetting, Category, Feature, Payment, SocialMedia,CustomBlogTopic, SubCategory, SubscriptionPlan, User, UserGeneratedTopic, UserParameter, UserSubscription, WordPress
from .serializers import BlogSerializer, BlogSettingSerializer,CustomBlogTopicSerializer, CategorySerializer, CustomUserSerializer, FeatureSerializer, SocialMediaSerializer, SubCategorySerializer, UserGeneratedTopicSerializer, UserParameterSerializer, UserSerializer, PaymentSerializer, SubscriptionPlanSerializer, WordPressSerializer
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from .serializers import UserSignupSerializer, UserLoginSerializer
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.conf import settings
from django.utils import timezone
from .encryption_utils import encrypt_with_public_key, decrypt_with_private_key
from django.db.models.functions import TruncDate,TruncWeek, TruncMonth
from django.db.models import Count, Max
from datetime import datetime, timedelta
from rest_framework.pagination import PageNumberPagination,LimitOffsetPagination
import os
from django.db.models import Q
from dotenv import load_dotenv
import stripe
import csv
from django.http import HttpResponse
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Review
from .serializers import ReviewSerializer

load_dotenv()
# Users Table


stripe.api_key = settings.STRIPE_SECRET_KEY
stripe_enpoint_secret=settings.STRIPE_ENDPOINT_SECRET



class CustomLimitOffsetPagination(LimitOffsetPagination):
    default_limit = 10  # Default limit (can be overridden by passing `limit`)
    max_limit = 100  # Maximum limit allowed


class StripeWebhookView(APIView):
    """
    Handle Stripe webhook events and update user subscription status.
    """
    def post(self, request, *args, **kwargs):
        """
        Handle Stripe webhook events.
        """
        payload = request.body
        
        sig_header = request.META['HTTP_STRIPE_SIGNATURE']
         

        try:
            event = stripe.Webhook.construct_event(payload, sig_header, stripe_enpoint_secret)
        except ValueError:
            return Response({'error': 'Invalid payload'}, status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError:
            return Response({'error': 'Invalid signature'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle Stripe events
        if event['type'] == 'checkout.session.completed':
            print("i am in checkout ==========")
            session = event['data']['object']
            user_id = session['metadata']['user_id']
            subscription_id = session['subscription']
            payment_id = session.get('payment_intent')
            amount = session.get('amount_total') / 100  # Convert amount from cents to dollars
            currency = session.get('currency')
            payment_status = session.get('payment_status')  # e.g., "paid"
            payment_method_types = session.get('payment_method_types', [])  
            try:
                user = User.objects.get(id=user_id)
                subscription = stripe.Subscription.retrieve(subscription_id)
                print("i am in subscription ==========",subscription)
                price_id = subscription['items']['data'][0]['price']['id']
                
                payment_method = payment_method_types[0] if payment_method_types else 'unknown'
                # Link the subscription to a plan in the database
                plan = SubscriptionPlan.objects.filter(price_id=price_id).first()
                print("plan----================",plan)
                print("dateeeee",subscription['start_date'])
                if plan:
                    UserSubscription.objects.create(
                        user_id=user,
                        plan_id=plan,
                        start_date = datetime.fromtimestamp(subscription['start_date']),
                        end_date = datetime.fromtimestamp(subscription['current_period_end']),
                        status='active',
                    )

                
                Payment.objects.create(
                    user=user,
                    plan=plan,
                    stripe_payment_id=session.get('id'),
                    stripe_invoice_id=session.get('invoice', ''),
                    stripe_subscription_id=subscription_id,
                    amount=amount,
                    currency=currency,
                    payment_method=payment_method,
                    payment_status=payment_status,
                    failure_reason='',
                )

                # Update the user's subscription details
                user.subscription_id = subscription_id
                user.subscription_status = 'active'
                # user.plan = plan
                user.save()

            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        elif event['type'] == 'invoice.payment_failed':
            invoice = event['data']['object']
            customer_id = invoice['customer']
            payment_failure_reason = invoice.get('failure_message', 'Unknown reason')
            payment_id = invoice.get('payment_intent', '')
            payment_status = session.get('payment_status')  # e.g., "paid"
            payment_method_types = session.get('payment_method_types', []) 

            try:
                user = User.objects.get(stripe_customer_id=customer_id)
                user.subscription_status = 'inactive'
                user.save()

                payment_method = payment_method_types[0] if payment_method_types else 'unknown'

                Payment.objects.create(
                    user=user,
                    plan=None,
                    stripe_payment_id=session.get('id'),
                    stripe_invoice_id=invoice.get('id', ''),
                    stripe_subscription_id=invoice.get('subscription', ''),
                    amount=invoice.get('amount_due', 0) / 100,  # Convert amount from cents to dollars
                    payment_method=payment_method,
                    payment_status=payment_status,
                    failure_reason=payment_failure_reason,
                )
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'status': 'success'}, status=status.HTTP_200_OK)



class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Create Stripe customer
            stripe_customer = stripe.Customer.create(
                email=user.email,
                metadata={"user_id": user.id}
            )
            user.stripe_customer_id = stripe_customer['id']
            user.save()

            # Create or get token for the user
            token, created = Token.objects.get_or_create(user=user)

            return Response({
                'message': 'User created successfully',
                'user_id': user.id,
                'email': user.email,
                'role': user.role,
                'token': token.key
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            # Authenticate user
            user = authenticate(request, username=email, password=password)
            
            if user:
                # Check user status
                if user.status != 'active':
                    return Response({
                        'error': 'Account is not active'
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Create or get token
                token, created = Token.objects.get_or_create(user=user)
                
                return Response({
                    'message': 'Login successful',
                    'user_id': user.id,
                    'email': user.email,
                    'role': user.role,
                    'token': token.key
                })
            
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Delete the token on logout
        request.user.auth_token.delete()
        return Response({
            'message': 'Successfully logged out'
        }, status=status.HTTP_200_OK)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'role': user.role,
            'company_name': user.company_name,
            'phone':user.phone,
            'status': user.status
        })
    


class DashboardViewset(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated] 


    def get_permissions(self):
        super_admin_only = [permissions.IsAuthenticated(), IsSuperAdmin()]
        admin_or_super_admin = [permissions.IsAuthenticated(), IsSuperAdminOrAdmin()]

        if self.action == 'user_count':
            return admin_or_super_admin
        
        if self.action == 'active_user_count':
            return admin_or_super_admin

       
        return super().get_permissions()

    @action(detail=False, methods=['GET'])
    def user_count(self, request):
        user = request.user
        admin_id = request.query_params.get('admin_id')  # Optional, for SuperAdmins

        if user.role == 'SuperAdmin':
            if admin_id:
                total_users = User.objects.filter(is_deleted=False, assigned_admin_id=admin_id).count()
                total_active_users = User.objects.filter(is_deleted=False, is_active=True, assigned_admin_id=admin_id).count()
            else:
                total_users = User.objects.filter(is_deleted=False).count()
                total_active_users = User.objects.filter(is_deleted=False, is_active=True).count()

        elif user.role == 'Admin':
            total_users = User.objects.filter(is_deleted=False, assigned_admin=user).count()
            total_active_users = User.objects.filter(is_deleted=False, is_active=True, assigned_admin=user).count()

        else:
            return Response({"error": "You do not have permission to access this data."}, status=status.HTTP_403_FORBIDDEN)

        return Response({
            "total_users": total_users,
            "total_active_users": total_active_users
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['GET'])
    def blog_count(self, request):
        user = request.user
        user_id = request.query_params.get('user_id')  # For SuperAdmin or Admin to filter by specific User
        admin_id = request.query_params.get('admin_id')  # For SuperAdmin to filter by Admin's Users

        if user.role == 'SuperAdmin':
            if user_id:
                # Blog count for specific User
                total_blogs = Blog.objects.filter(user_id=user_id).count()

            elif admin_id:
                # Blog count for specific Admin and their assigned Users + Admin themselves
                total_blogs = Blog.objects.filter(
                    Q(user_id=admin_id) | Q(user_id__assigned_admin_id=admin_id)
                ).count()

            else:
                # Total blog count (ALL blogs)
                total_blogs = Blog.objects.count()

        elif user.role == 'Admin':
            if user_id:
                # Admin can only view blogs for a User assigned to them
                try:
                    specific_user = User.objects.get(id=user_id, assigned_admin=user)
                except User.DoesNotExist:
                    return Response(
                        {"error": "User not found or not assigned to you."},
                        status=status.HTTP_404_NOT_FOUND
                    )
                total_blogs = Blog.objects.filter(user_id=specific_user).count()

            else:
                # Blog count for Admin + all Users assigned to this Admin
                total_blogs = Blog.objects.filter(
                    Q(user_id=user) | Q(user_id__assigned_admin=user)
                ).count()

        else:  # Normal User
            # Normal User can only view their own blog count
            total_blogs = Blog.objects.filter(user_id=user).count()

        return Response({"total_blogs": total_blogs}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["GET"])
    def social_media_post_count(self, request):
        user = request.user
        user_id = request.query_params.get("user_id")  # Optional: Filter by specific User
        admin_id = request.query_params.get("admin_id")  # Optional: Filter by Admin's Users

        queryset = SocialMedia.objects.all()

        # Apply role-based filtering
        if user.role == "SuperAdmin":
            if user_id:
                queryset = queryset.filter(user_id=user_id)
            elif admin_id:
                queryset = queryset.filter(Q(user_id=admin_id) | Q(user_id__assigned_admin_id=admin_id))
        elif user.role == "Admin":
            if user_id:
                # Ensure the user belongs to the admin
                if not User.objects.filter(id=user_id, assigned_admin=user).exists():
                    return Response(
                        {"error": "User not found or not assigned to you."},
                        status=status.HTTP_404_NOT_FOUND,
                    )
                queryset = queryset.filter(user_id=user_id)
            else:
                queryset = queryset.filter(Q(user_id=user) | Q(user_id__assigned_admin=user))
        else:  # Normal User
            queryset = queryset.filter(user_id=user)

        # Get all available platforms (assuming a field like PLATFORM_CHOICES in SocialMedia model)
        all_platforms = dict(SocialMedia.PLATFORM_CHOICES)  # Example: {'facebook': 'Facebook', 'twitter': 'Twitter'}

        # Get counts for existing platforms
        platform_counts = queryset.values("platform").annotate(post_count=Count("id"))

        # Convert to a dictionary for easy lookup
        platform_counts_dict = {item["platform"]: item["post_count"] for item in platform_counts}

        # Ensure all platforms are included with count 0 if missing
        final_counts = [{"platform": platform, "post_count": platform_counts_dict.get(platform, 0)}
                        for platform in all_platforms.keys()]

        return Response({"platform_counts": final_counts}, status=status.HTTP_200_OK)
    
    
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(is_deleted=False)
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated] 
    
   
    def get_permissions(self):
        if self.action == 'password_setup':
            return [permissions.AllowAny()]
        
        super_admin_only = [permissions.IsAuthenticated(), IsSuperAdmin()]
        admin_or_super_admin = [permissions.IsAuthenticated(), IsSuperAdminOrAdmin()]
        # admin_or_super_admin = [permissions.IsAuthenticated(), IsAdminOrSelf()]
        admin_or_assigned = [permissions.IsAuthenticated(), IsSuperAdminOrAdminOrAssigned()]

        if self.action in ['delete_user','add_user']:
            return super_admin_only
        
        if self.action in ['list_users', 'user_config']:
            return admin_or_super_admin

        if self.action in ['get_user', 'update_user']:
            return admin_or_assigned

        return super().get_permissions()





    @action(detail=False, methods=['POST'])
    def add_user(self, request, *args, **kwargs):
        data = request.data
        email = data.get('email')
        name = data.get('name')
        role = data.get('role', 'User')
        company_name = data.get('company_name')
        phone = data.get('phone')
        assigned_admin_id = data.get('assigned_admin')

        if not email or not name:
            return Response({"error": "Email and name are required."}, status=status.HTTP_400_BAD_REQUEST)


        assigned_admin = None
        if assigned_admin_id:
            try:
                assigned_admin = User.objects.get(id=assigned_admin_id, role='Admin')
            except User.DoesNotExist:
                return Response({"error": "Assigned admin not found or is not an Admin."}, status=status.HTTP_400_BAD_REQUEST)

        # Create user
        user = User.objects.create(
            username=email,
            email=email,
            name=name,
            role=role,
            company_name=company_name,
            phone=phone,
            assigned_admin=assigned_admin,
            is_active=False  # Initially inactive
        )
       
        stripe_customer = stripe.Customer.create(
                email=user.email,
                metadata={"user_id": user.id}
            )
        user.stripe_customer_id = stripe_customer['id']
        user.save()

        # Generate password setup link
        token = PasswordResetTokenGenerator().make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        frontend_base_url = f"{settings.FRONTEND_BASE_URL}/login/reset-password"
        password_setup_url = f"{frontend_base_url}/{uidb64}/{token}"

        # Send email
        send_mail(
            subject="Set Your Password",
            message=f"Click the link to set your password: {password_setup_url}",
            from_email='typhon@growyourbrand.ai',
            recipient_list=[email],
        )

        return Response({"message": "User added successfully and email sent."}, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['post'], url_path='password-setup/(?P<uidb64>[^/.]+)/(?P<token>[^/.]+)', permission_classes=[AllowAny])
    def password_setup(self, request, uidb64, token):
        """Handle password setup and activate the user."""
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        if password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid link."}, status=status.HTTP_400_BAD_REQUEST)

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_401_UNAUTHORIZED)

        # Set password and activate user
        user.set_password(password)
        user.is_active = True
        user.save()

        return Response({"message": "Password set successfully."}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['get'])
    def list_users(self, request):
        """
        - SuperAdmin: Can see all users.
        - Admin: Can see only their assigned users.
        """
        order = request.query_params.get('order', 'desc')
        users = User.objects.get_users_for_role(request.user)
        search_query = request.query_params.get('search', '').strip() 
        all_users = request.query_params.get('all', 'false') == 'true'
        role_filter = request.query_params.get('role', None)  # Role filtering
        status_filter = request.query_params.get('status', None) 

        if role_filter:
            role_filter = role_filter.split(',')
            users = users.filter(role__in=role_filter)  
        if status_filter:
            users = users.filter(status=status_filter)   

            
        if search_query:
            users = users.filter(
                Q(username__icontains=search_query) |  # Search in username
                Q(email__icontains=search_query) |  # Search in email
                Q(role__icontains=search_query) |  # Search in role (assuming role is a string field)
                Q(status__icontains=search_query)  # Search in status (assuming status is a string field)
            )

        if order == 'asc':
            users = users.order_by('created_at')  # Ascending order
        else:
            users = users.order_by('-created_at') 

        if not users.exists():
            return Response({"error": "no match found"}, status=status.HTTP_200_OK)
        
        if all_users:
            serializer = self.get_serializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        paginator = CustomLimitOffsetPagination()
        # paginator.page_size = 10  # You can adjust the page size here
        result_page = paginator.paginate_queryset(users, request)
        
        serializer = self.get_serializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

  

    @action(detail=True, methods=['get'])
    def get_user(self, request, pk=None):
        """
        Custom function to retrieve details of a particular user by ID.
        Access is controlled by IsSuperAdminOrAdminOrAssigned.
        """
        user = get_object_or_404(User, id=pk, is_deleted=False)

        serializer = self.serializer_class(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['put'])
    def update_user(self, request, pk=None):
        """
        Custom function to update a user's details by ID.
        """
        user = get_object_or_404(User, id=pk,is_deleted=False)

        # Check if user has permission to update this user
        self.check_object_permissions(request, user)

        # Prevent non-SuperAdmins from modifying the 'role' field
        if request.user.role != 'SuperAdmin':
            request.data.pop('role', None)  # Remove 'role' field if it exists
        
        request.data.pop('email', None)  # Remove 'email' field if it exists

        
        serializer = self.serializer_class(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'user': serializer.data,
                'message': 'User updated successfully.'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['delete'])
    def delete_user(self, request, pk=None):
        """
        Custom function to delete a user by ID.
        """
        try:
            user = User.objects.get(id=pk, is_deleted=False)
            user.soft_delete()
            return Response({'message': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")

    @action(detail=False, methods=['get'])
    def user_config(self, request):
        """
        Retrieve settings for all users, combining UserParameter and WordPress data.
        """
        users = User.objects.prefetch_related(
            'parameters',
            'wordpress_accounts'
        ).filter(
        parameters__isnull=False, 
        wordpress_accounts__isnull=False,
        wordpress_accounts__is_deleted=False
        ).distinct()
        print(users)
        # print(users.parameters)
        # Debug prints
        # for user in users:
        #     print(f"User: {user.email}")
        #     print(f"Parameters: {user.parameters.all().first()}")  # Check if parameters exist
        #     print(f"WordPress accounts: {user.wordpress_accounts.all()}")
        
        serializer = CustomUserSerializer(users, many=True)
        # print("Serialized data:", serializer.data)  # See what's in the serializer
        return Response(serializer.data, status=status.HTTP_200_OK)    
        




class BlogSettingViewSet(viewsets.ModelViewSet):
    queryset = BlogSetting.objects.all()
    serializer_class = BlogSettingSerializer
    permission_classes = [permissions.IsAuthenticated, ]

   
    def get_permissions(self):
        """
        Custom permission logic for different actions.
        """
        if self.action in ['update_blog_setting', 'get_blog_setting','delete_blog_setting']:
            return [BlogSettingPermission()]

        return [IsSuperAdminOrAdminOrAssigned()]
        
    
    def get_queryset(self):
        """
        Override to ensure users can only access their own blog settings.
        """
        return BlogSetting.objects.filter(user_id=self.request.user,is_deleted=False)

    @action(detail=False, methods=['POST'])
    def add_blog_setting(self, request):
        """
        Add a new blog setting for the current user without using serializer's create method.
        """
        try:
            # Extract data from request
            name = request.data.get('name')
            
          
            frequency_value = request.data.get('frequency_value')
            cycle_interval = request.data.get('cycle_interval')
            wordpress_id = request.data.get('wordpress_id')
            user_id=request.data.get('user_id')

            # Validate required fields
            if not all([name, frequency_value, cycle_interval]):
                return Response({"error": "Missing required fields."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise NotFound(detail="User not found.")
            self.check_object_permissions(request, user)
            # Create the object directly using ORM
            blog_setting = BlogSetting.objects.create(
                name=name,
              

                frequency_value=frequency_value,
                cycle_interval=cycle_interval,
                wordpress_id_id=wordpress_id,  # Use wordpress_id_id for FK (ID only)
                user_id=user  # Current logged-in user
            )

            # Serialize the newly created object
            serializer = self.get_serializer(blog_setting)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


    @action(detail=False, methods=['PATCH'])
    def update_blog_setting(self, request, pk=None):
        """
        Partially update a specific blog setting.
        Prevent changing the user_id.
        """
        instance = BlogSetting.objects.get(id=pk,is_deleted=False)

        self.check_object_permissions(request, instance)
        data = request.data.copy()

        serializer = self.serializer_class(instance, data=data, partial=True)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Exception as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    @action(detail=True, methods=['DELETE'])
    def delete_blog_setting(self, request, pk=None):
        """
        Delete a specific blog setting.
        """
        try:
            instance = BlogSetting.objects.get(id=pk)
            self.check_object_permissions(request, instance)
            instance.soft_delete()
            return Response(
                {"detail": "Blog setting deleted successfully."},
                status=status.HTTP_204_NO_CONTENT,
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['GET'])
    def get_blog_setting(self, request, pk=None):
        """ Override to ensure users can only access their own blog settings.
        Retrieve a specific blog setting.
        """
        try:
            instance =self.get_object()
            # self.check_object_permissions(request, instance)
            serializer = self.serializer_class(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['GET'])
    def list_blog_setting(self, request,pk=None):
        """
        List all blog settings for the current user.
        """
        try:
            user = User.objects.get(id=pk)
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")
        self.check_object_permissions(request, user)

        try:
            queryset = BlogSetting.objects.filter(user_id=pk,is_deleted=False)
            serializer = self.serializer_class(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class WordPressViewSet(viewsets.ModelViewSet):
    """
    A ViewSet for managing WordPress settings.
    """
    queryset = WordPress.objects.all()
    serializer_class = WordPressSerializer
    permission_classes = [permissions.IsAuthenticated,IsAdminOrSelf]

    def get_permissions(self):
        """
        Custom permission logic for different actions.
        """
        if self.action in ['update_wordpress_setting', 'get_wordpress_setting','delete_wordpress_setting']:
            return [WordPressPermission()]

        return [IsSuperAdminOrAdminOrAssigned()]

    
    def get_queryset(self):
        """
        Restrict query based on the user role and exclude soft-deleted records.
        """
        user = self.request.user

        if user.role == "SuperAdmin":
            return WordPress.objects.filter(is_deleted=False)

        if user.role == "Admin":
            return (WordPress.objects.filter(user__assigned_admin=user, is_deleted=False) | 
                    WordPress.objects.filter(user=user, is_deleted=False))

        return WordPress.objects.filter(user=user, is_deleted=False)

    @action(detail=False, methods=['POST'])
    def add_wordpress_setting(self, request):
        """
        Add a new WordPress setting for the current user.
        """
        try:
            try:
                user = User.objects.get(id=request.data.get('user_id'))
            except User.DoesNotExist:
                raise NotFound(detail="User not found.")
            self.check_object_permissions(request, user)
              
            wordpress_api_key = request.data.get("wordpress_api_key")
           
            if wordpress_api_key:
                wordpress_api_key = request.data.get("wordpress_api_key")
        
                if request.data.get("is_encrypted",False) != True:
                    print("i am in encrypting")
                    wordpress_api_key = encrypt_with_public_key(wordpress_api_key)
            wordpress_setting = WordPress.objects.create(
                user=user,  # Automatically set the current user
                wordpress_username=request.data.get("wordpress_username"),  # Retrieve from the request data
                wordpress_key_name=request.data.get("wordpress_key_name"), 
                wordpress_api_key=wordpress_api_key,    # Retrieve from the request data
                wordpress_url=request.data.get("wordpress_url"),
                wordpress_uuid=request.data.get('wordpress_uuid')   # Retrieve from the request data
            )
            serializer = self.get_serializer(wordpress_setting)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['PATCH']) 
    def update_wordpress_setting(self, request, pk=None):
        """
        Partially update a specific WordPress setting.
        """
        try:
            # Retrieve the WordPress instance
            instance = WordPress.objects.get(id=pk)
                        
            # Check permissions
            self.check_object_permissions(request, instance)
            
            # Copy and process the incoming data
            data = request.data.copy()
            wordpress_api_key = request.data.get("wordpress_api_key")
            if wordpress_api_key:
                wordpress_api_key = request.data.get("wordpress_api_key")
                
                # Encrypt the key if it's raw (24 characters long)
         
                if request.data.get("is_encrypted",False) != True:
            
                    wordpress_api_key = encrypt_with_public_key(wordpress_api_key)
                # Update the API key in the data
                    data["wordpress_api_key"] = wordpress_api_key

            # Serialize and save the updated instance
            serializer = self.serializer_class(instance, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except WordPress.DoesNotExist:
            return Response({"error": "WordPress setting not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['DELETE'])
    def delete_wordpress_setting(self, request, pk=None):
        """
        Delete a specific WordPress setting.
        """
        try:
            instance = WordPress.objects.get(id=pk)
            self.check_object_permissions(request,instance)
            instance.soft_delete()
            return Response({"message": "WordPress setting deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['GET'])
    def get_wordpress_setting(self, request, pk=None):
        """
        Retrieve a specific WordPress setting.
        """
        try:
            instance = self.get_object()

            # self.check_object_permissions(request, instance.user)

            serializer = self.get_serializer(instance)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['GET'])
    def list_wordpress_settings(self, request,pk=None):
        """
        List all WordPress settings for the current user.
        """
        try:
            user = User.objects.get(id=pk)
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")
        self.check_object_permissions(request, user)

        try:
            queryset =WordPress.objects.filter(user_id=pk,is_deleted=False)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

       


class StripeViewSet(viewsets.ModelViewSet):
    serializer_class=SubscriptionPlanSerializer
    queryset=SubscriptionPlan.objects.none()
    permission_classes=[permissions.IsAuthenticated]


    @action(detail=False, methods=['GET'])
    def check_subscription(self, request):
        """
        Check the user's subscription status and return available plans if no active subscription exists.
        """
        user = request.user

        # Check if the user has an active subscription
        if user.subscription_status == 'active':
            user_subscription = UserSubscription.objects.filter(user_id=user, status='active').first()
            print(user_subscription)
            subscription_serializer = SubscriptionPlanSerializer(user_subscription.plan_id)
            return Response({
                "has_active_plan":True,
                "message": "User has an active subscription",
                "subscription": subscription_serializer.data
            }, status=status.HTTP_200_OK)

        # If no active subscription, fetch available plans
        plans = SubscriptionPlan.objects.all()
        serializer = SubscriptionPlanSerializer(plans, many=True)

        return Response({
            "has_active_plan":False,
            "message": "User does not have an active subscription",
            "available_plans": serializer.data
        }, status=status.HTTP_200_OK)

    @action(detail=False,methods=['POST'])
    def create_checkout_session(self, request):
        """
        Create a Stripe Checkout session for the selected plan.
        """
        user = request.user
        price_id = request.data.get('price_id')  # Stripe price ID
        success_url = settings.STRIPE_SUCCESS_URL
        cancel_url = settings.STRIPE_CANCEL_URL

        if not price_id:
            return Response({"error": "price ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not success_url or not cancel_url:
            return Response({"error": "Both success_url and cancel_url are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session = stripe.checkout.Session.create(
                customer=user.stripe_customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={"user_id": user.id},
            )
            return Response({"checkout_url": session['url']}, status=status.HTTP_200_OK)
        except stripe.error.StripeError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        


    








class SubscriptionPlanViewSet(viewsets.ModelViewSet):
    queryset = SubscriptionPlan.objects.all()
    serializer_class = SubscriptionPlanSerializer
    permission_classes = [permissions.IsAuthenticated] 

    def get_queryset(self):
        """Ensure soft-deleted plans are excluded from listings."""
        return SubscriptionPlan.objects.filter(is_deleted=False)


    def get_permissions(self):
        """
        Assign specific permissions based on the action being performed.
        """
        if self.action == 'add_subscription_plan':
            return [IsSuperAdmin()]  # Only SuperAdmin can create a plan
        elif self.action == 'list_subscription_plans':
            return [AllowAny()]  # Both Admin and SuperAdmin can view all plans
        elif self.action == 'get_subscription_plan':
            return [IsSuperAdminOrAdminOrAssigned()]  # Users can see their own, Admins see assigned users, SuperAdmin sees all
        elif self.action == 'update_subscription_plan':
            return [IsSuperAdmin()]  # Only SuperAdmin can update a plan
        elif self.action == 'delete_subscription_plan':
            return [IsSuperAdmin()]  # Only SuperAdmin can delete a plan
        return super().get_permissions()


    @action(detail=False, methods=['POST'])
    def add_subscription_plan(self, request):
        """
        Create a subscription plan in Stripe and save it in the database.
        """
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data

            try:
                # 1. Create Product in Stripe
                product = stripe.Product.create(
                    name=data['name'],
                    description=data.get('description', ''),
                )

                # 2. Create Price in Stripe
                price = stripe.Price.create(
                    unit_amount=int(data['price_per_month'] * 100),  # Convert dollars to cents
                    currency=data['currency'].lower(),
                    recurring={"interval": data['frequency']},  # 'month' or 'year'
                    product=product.id,
                )

                # 3. Save Subscription Plan in the Database
                subscription_plan = serializer.save(price_id=price.id,product_id=product.id)

                return Response(SubscriptionPlanSerializer(subscription_plan).data, status=status.HTTP_201_CREATED)

            except stripe.error.StripeError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    @action(detail=False, methods=['GET'])
    def list_subscription_plans(self, request):
        """
        List all subscription plans.
        """
        queryset = self.get_queryset()
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['GET'])
    def get_subscription_plan(self, request):
        """ 
        Retrieve the active subscription plan for the specified user or the current user.
        """
        user_id = request.query_params.get('user_id')  # Allow specifying the user ID in the query parameters
       
        # If user_id is provided, validate that the requesting user has permission
       
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        

        # Retrieve the user's active subscription plan
        try:
            subscription = UserSubscription.objects.filter(user_id=user, status='active').first()
            if not subscription:
                return Response(
                    {"error": "No active subscription plan found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            serializer = SubscriptionPlanSerializer(subscription.plan_id)
            response_data = {
            "plan": serializer.data,
            "start_date": subscription.start_date,
            "end_date": subscription.end_date,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "An error occurred while retrieving the subscription plan.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
                

    @action(detail=True, methods=['PATCH'])
    def update_subscription_plan(self, request, pk=None):
        """
        Update a specific subscription plan in the database and sync with Stripe.
        - Ensures that 'price_id' is not manually updated.
        - Updates the product name in Stripe if changed.
        - Creates a new price in Stripe if the price changes (since Stripe doesn't allow price updates).
        """
        try:
            instance = self.get_object()
            data = request.data
            stripe_product_id = instance.product_id  # Use the correct Product ID, not price_id
            old_price_id=instance.price_id
            # Prevent direct update of price_id
            if "price_id" in data:
                return Response({"error": "You cannot update price_id directly"}, status=status.HTTP_400_BAD_REQUEST)

            updated_fields = {}

            # 1. Check if the Name is Updated
            if "name" in data and data["name"] != instance.name:
                try:
                    # Update Product Name in Stripe (use product_id instead of price_id)
                    stripe.Product.modify(
                        stripe_product_id,
                        name=data["name"]
                    )
                    updated_fields["name"] = data["name"]
                except stripe.error.StripeError as e:
                    return Response({"error": f"Failed to update Stripe product: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

            # 2. Check if Price is Updated


            price_changed = "price_per_month" in data and float(data["price_per_month"]) != float(instance.price_per_month)
            interval_changed = "frequency" in data and data["frequency"] != instance.frequency

# If either price or interval is updated, create a new price
            if price_changed or interval_changed:
                try:
                    # Create a New Price in Stripe
                    stripe.Price.modify(old_price_id, active=False)
                    new_price = stripe.Price.create(
                        unit_amount=int(float(data.get("price_per_month", instance.price_per_month)) * 100), # Convert dollars to cents
                        currency=instance.currency.lower(),
                        recurring={"interval": instance.frequency},
                        product=stripe_product_id  # Use correct product ID
                    )

                    # Store the new price ID
                    if price_changed:
                        updated_fields["price_per_month"] = data["price_per_month"]
                    if interval_changed:
                        updated_fields["frequency"] = data["frequency"]

                   

                except stripe.error.StripeError as e:
                    return Response({"error": f"Failed to update price in Stripe: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

            # 3. Update the Django Database Entry
            serializer = self.serializer_class(instance, data=data, partial=True)
            if serializer.is_valid():
                serializer.save(**updated_fields)  # Apply changes
                return Response(serializer.data, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Subscription Plan not found"}, status=status.HTTP_404_NOT_FOUND)



    @action(detail=True, methods=['DELETE'])
    def delete_subscription_plan(self, request, pk=None):
        """
        Delete a specific subscription plan by its ID.
        - Removes the subscription from both the database and Stripe.
        """
        try:
            instance = self.get_object()

            # 1️⃣ Delete Product and Price from Stripe
            try:
                # Deleting Product from Stripe
                stripe.Price.modify(instance.price_id, active=False)

            # Archive Product (Stripe does not allow deleting products with associated prices)
                stripe.Product.modify(instance.product_id, active=False)
            except stripe.error.StripeError as e:
                return Response({"error": f"Failed to delete from Stripe: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

            # 2️⃣ Delete the Subscription Plan from the database
            instance.soft_delete()

            return Response(
                {"message": "Subscription Plan and associated data deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )

        except SubscriptionPlan.DoesNotExist:
            return Response(
                {"error": "Subscription Plan not found"}, status=status.HTTP_404_NOT_FOUND
            )

    action(detail=False, methods=['POST'])
    def cancel_subscription(self, request):
        """
        Cancel a user's subscription at the end of the current billing period.
        - The subscription remains active until the end of the current period
        - Status will be updated to 'canceled' but access continues until period end
        """
        user_id = request.data.get('user_id')
        
        try:
            # Validate user exists
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            
            # Find the active subscription for this user
            subscription = UserSubscription.objects.filter(user_id=user, status='active').first()
            if not subscription:
                return Response(
                    {"error": "No active subscription found for this user."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            
            # Cancel the subscription in Stripe
            try:
                stripe_subscription_id = subscription.stripe_subscription_id
                
                # Cancel at period end (Stripe will continue the subscription until the end of the period)
                stripe_response = stripe.Subscription.modify(
                    stripe_subscription_id,
                    cancel_at_period_end=True
                )
                
                # Update local subscription status
                subscription.status = 'canceling'  # Special status indicating it's active but will be canceled
                subscription.save()
                
                return Response({
                    "message": "Subscription has been scheduled for cancellation at the end of the current billing period.",
                    "current_period_end": datetime.fromtimestamp(stripe_response.current_period_end),
                }, status=status.HTTP_200_OK)
                
            except stripe.error.StripeError as e:
                return Response(
                    {"error": f"Failed to cancel subscription in Stripe: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            return Response(
                {"error": "An error occurred while canceling the subscription.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )



class PaymentViewSet(viewsets.ModelViewSet):
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Payment.objects.filter(user_id=self.request.user)

    @action(detail=False, methods=['POST'])
    def add_payment(self, request):
        data = request.data.copy()
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # @action(detail=True, methods=['PATCH'])
    # def update_payment(self, request, pk=None):
    #     instance = self.get_object()
    #     data = request.data.copy()
    #     serializer = self.get_serializer(instance, data=data, partial=True)
    #     if serializer.is_valid():
    #         try:
    #             serializer.save()
    #             return Response(serializer.data, status=status.HTTP_200_OK)
    #         except Exception as e:
    #             return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # @action(detail=True, methods=['DELETE'])
    # def delete_payment(self, request, pk=None):
    #     instance = self.get_object()
    #     try:
    #         instance.delete()
    #         return Response(status=status.HTTP_204_NO_CONTENT)
    #     except Exception as e:
    #         return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['GET'])
    def get_payment(self, request, pk=None):
        instance = self.get_object()
        serializer = self.get_serializer(instance)    
        return Response(serializer.data)
    
    @action(detail=True, methods=['GET'])
    def get_user_payment(self, request):
        """
        Retrieve payment details for the specified user or the currently logged-in user.
        """
        user_id = request.query_params.get('user_id')  # Allow specifying the user ID in the query parameters

        # If user_id is provided, validate that the requesting user has permission
     
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
    

        # Retrieve the payments for the specified or current user
        payments = Payment.objects.filter(user_id=user).order_by('-payment_date')

        if not payments.exists():
            return Response(
                {"error": "No payment records found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Serialize the payment data
        serializer = self.get_serializer(payments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


    @action(detail=False, methods=['GET'])
    def list_payments(self, request):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

class BlogViewSet(viewsets.ModelViewSet):
    serializer_class = BlogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == "SuperAdmin":
            return Blog.objects.all()
        if user.role == "Admin":
            return Blog.objects.filter(user_id__assigned_admin=user) | Blog.objects.filter(user_id=user)
        return Blog.objects.filter(user_id=user)

    def get_filtered_data(self, queryset, start_date, end_date, trunc_func):
        """Fetch blog statistics with grouping based on time period."""
        return (
            queryset.filter(publish_date__date__range=[start_date, end_date])
            .annotate(group=trunc_func("publish_date"))
            .values("group")
            .annotate(blogs_posted=Count("id"))
            .order_by("group")
        )

    def get_date_range(self, period):
        """Get the start and end dates for the requested period."""
        today = datetime.today()
        # today = datetime(2025, 2, 19)
        # print("today",today)

        # if period == "this_week":
        #     return today - timedelta(days=today.weekday()), today

        if period == "this_week":
            start_date = today - timedelta(days=today.weekday())  # Monday of this week
            end_date = today if today.weekday() < 5 else start_date + timedelta(days=4)  # If today is Sat/Sun, end at Friday
            return start_date, end_date
        # elif period == "last_week":
        #     end_date = today - timedelta(days=today.weekday() + 1)
        #     return end_date - timedelta(days=6), end_date
        elif period == "last_week":
            # Find last Friday
            end_date = today - timedelta(days=today.weekday() + 3)  # Go back to previous Friday
            # Find last Monday
            start_date = end_date - timedelta(days=4)  # Go back 4 days to Monday
            return start_date, end_date
        elif period == "last_month":
            start_date = (today.replace(day=1) - timedelta(days=1)).replace(day=1)
            end_date = (start_date + timedelta(days=31)).replace(day=1) - timedelta(days=1)
            return start_date, end_date
        elif period == "this_month":
            start_date = today.replace(day=1)
            return start_date, today
        elif period == "this_year":
            start_date = today.replace(month=1, day=1)
            return start_date, today
        elif period == "last_year":
            return today.replace(month=1, day=1, year=today.year - 1), today.replace(month=12, day=31, year=today.year - 1)
        return None, None

    def generate_full_date_list(self, start_date, end_date, period):
        """Generate all required dates/weeks/months based on the selected period."""
        full_range = []
        current = start_date

        if period in ["this_week", "last_week"]:
            while current <= end_date:
                full_range.append(current.strftime("%d-%m-%Y"))
                current += timedelta(days=1)
        elif period in ["this_month", "last_month"]:
            while current <= end_date:
                week_number = (current - start_date).days // 7 + 1
                full_range.append(f"Week {week_number}")
                current += timedelta(days=7)
        elif period in ["this_year", "last_year"]:
            for month in range(1, 13):
                if start_date.year == end_date.year and month > end_date.month:
                    break
                full_range.append(datetime(start_date.year, month, 1).strftime("%b"))
        return full_range

    def format_data(self, raw_data, period, start_date, end_date):
        """Ensure all expected time points exist, even if blog count is zero."""
        month_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        data_dict = {item["group"].strftime("%d-%m-%Y") if period in ["this_week", "last_week"] else
                     f"Week {index + 1}" if period in ["this_month", "last_month"] else
                     month_names[item["group"].month - 1]: item["blogs_posted"]
                     for index, item in enumerate(raw_data)}

        full_labels = self.generate_full_date_list(start_date, end_date, period)
        formatted_data = [{"label": label, "blogs_posted": data_dict.get(label, 0)} for label in full_labels]
        return formatted_data

    @action(detail=False, methods=["GET"])
    def blog_statistics(self, request):
        period = request.query_params.get("period", "this_week")
        start_date, end_date = self.get_date_range(period)

        print("sd",start_date)
        print("sd",end_date)
        # end_date ="2025-02-22 10:51:10.371399"

        if not start_date or not end_date:
            return Response({"error": "Invalid period"}, status=status.HTTP_400_BAD_REQUEST)

        trunc_mapping = {
            "this_week": TruncDate,
            "last_week": TruncDate,
            "last_month": TruncWeek,
            "this_month": TruncWeek,
            "last_year": TruncMonth,
            "this_year": TruncMonth
        }

        raw_data = self.get_filtered_data(self.get_queryset(), start_date, end_date, trunc_mapping[period])
        formatted_data = self.format_data(raw_data, period, start_date, end_date)

        return Response({period: formatted_data}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['GET'])
    def list_blogs(self, request):
        """
        List all blogs for the logged-in user or all blogs if the user is an admin.
        """
        order = request.query_params.get('order', 'desc')  # Default to descending order
        
        search_query = request.query_params.get('search', '').strip()
        blogs = self.get_queryset()
        start_date = request.query_params.get('start_date', None)  # Date Range Start
        end_date = request.query_params.get('end_date', None)

    # Apply sorting based on order query param
        if search_query:
            blogs = blogs.filter(
                Q(title__icontains=search_query) |
                Q(link__icontains=search_query) |
                Q(user_id__username__icontains=search_query)  # Adjust this field based on actual DB schema
            )

        if start_date and end_date:
            try:
                start_date = datetime.strptime(start_date, "%Y-%m-%d")
                end_date = datetime.strptime(end_date, "%Y-%m-%d")
                blogs = blogs.filter(publish_date__date__range=[start_date, end_date])
            except ValueError:
                return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

        
        
        if order == 'asc':
            blogs = blogs.order_by('publish_date')  # Ascending order
        else:
            blogs = blogs.order_by('-publish_date')  #
       
        paginator = CustomLimitOffsetPagination()
        # paginator.page_size = 10  # You can adjust the page size here
        result_page = paginator.paginate_queryset(blogs, request)
        
        serializer = self.get_serializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=False, methods=['POST'])
    def add_blog(self, request):
        """
        Add a new blog for the logged-in user.
        """
        data = request.data.copy()
       
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            blog = serializer.save()
            return Response(self.get_serializer(blog).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['GET'])
    def get_blog_from_wordpress(self, request, pk=None):
        # Get the blog instance
        instance = get_object_or_404(Blog, id=pk)
        
        # Extract the WordPress post ID
        wordpress_post_id = instance.wordpress_key
        wordpress_url=instance.setting_id.wordpress_id.wordpress_url
        wordpress_username=instance.setting_id.wordpress_id.wordpress_username
        encrypted_api_key=instance.setting_id.wordpress_id.wordpress_api_key
        wordpress_api_key=''
        try:
            wordpress_api_key = decrypt_with_private_key(encrypted_api_key)
            print("Success:", wordpress_api_key)
        except Exception as e:
            print(f"Detailed error: {str(e)}")
      
        if not wordpress_post_id:
            return Response({"error": "WordPress key is not set for this blog."},
                            status=status.HTTP_400_BAD_REQUEST)
        
        # Define the WordPress API endpoint
        credentials = (wordpress_username, wordpress_api_key)
        wp_headers = {'Content-Type': 'application/json'}
        wordpress_api_url = f"{wordpress_url}/wp-json/wp/v2/posts/{wordpress_post_id}"
        try:
            # Make the GET request to fetch the WordPress post
            response = requests.get(wordpress_api_url, headers=wp_headers, auth=credentials)
            response.raise_for_status()  # Raise an error for bad HTTP status codes
            wordpress_data = response.json()
            # Return the WordPress post content in the response
            return Response({
                "title": wordpress_data.get("title", {}).get("rendered", ""),
                "content": wordpress_data.get("content", {}).get("rendered", ""),
                "excerpt": wordpress_data.get("excerpt", {}).get("rendered", ""),
                "date": wordpress_data.get("date", ""),
                "author": wordpress_data.get("author", "")
            }, status=status.HTTP_200_OK)
        except requests.exceptions.RequestException as e:
            # Handle errors while making the GET request
            return Response({"error": f"Failed to fetch blog from WordPress: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    @action(detail=True, methods=['patch'])
    def update_blog_to_wordpress(self, request, pk=None):
        # Get the blog instance
        instance = get_object_or_404(Blog, id=pk)
        # Extract WordPress credentials and API details
        wordpress_post_id = instance.wordpress_key
        wordpress_url = instance.setting_id.wordpress_id.wordpress_url
        wordpress_username = instance.setting_id.wordpress_id.wordpress_username
        encrypted_api_key=instance.setting_id.wordpress_id.wordpress_api_key
      
        wordpress_api_key = decrypt_with_private_key(encrypted_api_key)
       
        if not wordpress_post_id:
            return Response({"error": "WordPress key is not set for this blog."},
                            status=status.HTTP_400_BAD_REQUEST)
        # Define the WordPress API endpoint
        credentials = (wordpress_username, wordpress_api_key)
        wp_headers = {'Content-Type': 'application/json'}
        wordpress_api_url = f"{wordpress_url}/wp-json/wp/v2/posts/{wordpress_post_id}"
        # Get the data from the request to update the WordPress post
        title = request.data.get("title", instance.title)
        content = request.data.get("content")
        excerpt = request.data.get("excerpt", "")
        author = request.data.get("author", "")
        # Payload to update the WordPress post
        payload = {
            "title": title,
            "content": content,
            "excerpt": excerpt,
            "author": author,
        }
        try:
            # Make the PUT request to update the WordPress post
            response = requests.put(wordpress_api_url, headers=wp_headers, auth=credentials, json=payload)
            response.raise_for_status()  # Raise an error for bad HTTP status codes
            wordpress_data = response.json()
            instance.title = title
            instance.updated_at = timezone.now()
            instance.refresh_count += 1
            instance.save()
            # Return the updated WordPress post content in the response
            return Response({
                "id": wordpress_data.get("id", ""),
                "title": wordpress_data.get("title", {}).get("rendered", ""),
                "content": wordpress_data.get("content", {}).get("rendered", ""),
                "excerpt": wordpress_data.get("excerpt", {}).get("rendered", ""),
                "date": wordpress_data.get("date", ""),
                "author": wordpress_data.get("author", "")
            }, status=status.HTTP_200_OK)
        except requests.exceptions.RequestException as e:
            # Handle errors while making the PUT request
            return Response({"error": f"Failed to update blog on WordPress: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SocialMediaViewSet(viewsets.ModelViewSet):
    serializer_class = SocialMediaSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == "SuperAdmin":
            return SocialMedia.objects.all()
        if user.role == "Admin":
            return SocialMedia.objects.filter(user_id__assigned_admin=user) | SocialMedia.objects.filter(user_id=user)
        return SocialMedia.objects.filter(user_id=user)

    def get_filtered_data(self, queryset, start_date, end_date, trunc_func, platform=None):
        """Fetch social media statistics with grouping based on time period and optional platform filtering."""
        filtered_queryset = queryset.filter(publish_date__date__range=[start_date, end_date])
        
        if platform:
            filtered_queryset = filtered_queryset.filter(platform=platform)
            
        return (
            filtered_queryset
            .annotate(group=trunc_func("publish_date"))
            .values("group")
            .annotate(posts_count=Count("id"))
            .order_by("group")
        )

    def get_date_range(self, period):
        """Get the start and end dates for the requested period."""
        today = datetime.today()

        if period == "this_week":
            start_date = today - timedelta(days=today.weekday())  # Monday of this week
            end_date = today if today.weekday() < 5 else start_date + timedelta(days=4)  # If today is Sat/Sun, end at Friday
            return start_date, end_date
        elif period == "last_week":
            # Find last Friday
            end_date = today - timedelta(days=today.weekday() + 3)  # Go back to previous Friday
            # Find last Monday
            start_date = end_date - timedelta(days=4)  # Go back 4 days to Monday
            return start_date, end_date
        elif period == "last_month":
            start_date = (today.replace(day=1) - timedelta(days=1)).replace(day=1)
            end_date = (start_date + timedelta(days=31)).replace(day=1) - timedelta(days=1)
            return start_date, end_date
        elif period == "this_month":
            start_date = today.replace(day=1)
            return start_date, today
        elif period == "this_year":
            start_date = today.replace(month=1, day=1)
            return start_date, today
        elif period == "last_year":
            return today.replace(month=1, day=1, year=today.year - 1), today.replace(month=12, day=31, year=today.year - 1)
        return None, None

    def generate_full_date_list(self, start_date, end_date, period):
        """Generate all required dates/weeks/months based on the selected period."""
        full_range = []
        current = start_date

        if period in ["this_week", "last_week"]:
            while current <= end_date:
                full_range.append(current.strftime("%d-%m-%Y"))
                current += timedelta(days=1)
        elif period in ["this_month", "last_month"]:
            while current <= end_date:
                week_number = (current - start_date).days // 7 + 1
                full_range.append(f"Week {week_number}")
                current += timedelta(days=7)
        elif period in ["this_year", "last_year"]:
            for month in range(1, 13):
                if start_date.year == end_date.year and month > end_date.month:
                    break
                full_range.append(datetime(start_date.year, month, 1).strftime("%b"))
        return full_range

    def format_data(self, raw_data, period, start_date, end_date):
        """Ensure all expected time points exist, even if post count is zero."""
        month_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        data_dict = {item["group"].strftime("%d-%m-%Y") if period in ["this_week", "last_week"] else
                     f"Week {index + 1}" if period in ["this_month", "last_month"] else
                     month_names[item["group"].month - 1]: item["posts_count"]
                     for index, item in enumerate(raw_data)}

        full_labels = self.generate_full_date_list(start_date, end_date, period)
        formatted_data = [{"label": label, "posts_count": data_dict.get(label, 0)} for label in full_labels]
        return formatted_data






    @action(detail=False, methods=["GET"])
    def social_media_statistics(self, request):
        period = request.query_params.get("period", "this_week")
        platform = request.query_params.get("platform", None)  # Optional platform filter
        
        start_date, end_date = self.get_date_range(period)

        if not start_date or not end_date:
            return Response({"error": "Invalid period"}, status=status.HTTP_400_BAD_REQUEST)

        trunc_mapping = {
            "this_week": TruncDate,
            "last_week": TruncDate,
            "last_month": TruncWeek,
            "this_month": TruncWeek,
            "last_year": TruncMonth,
            "this_year": TruncMonth
        }

        raw_data = self.get_filtered_data(self.get_queryset(), start_date, end_date, trunc_mapping[period], platform)
        formatted_data = self.format_data(raw_data, period, start_date, end_date)

        response_data = {period: formatted_data}
        
        # Add platform info to the response if filtered
        if platform:
            response_data["platform"] = platform
            
        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['GET'])
    def list_posts(self, request):
        """
        List all social media posts with optional filtering by platform.
        """
        order = request.query_params.get('order', 'desc')  # Default to descending order
        platform = request.query_params.get('platform', None)  # Filter by platform
        search_query = request.query_params.get('search', '').strip()
        start_date = request.query_params.get('start_date', None)
        end_date = request.query_params.get('end_date', None)
        
        posts = self.get_queryset()
        
        # Filter by platform if specified
        if platform:
            posts = posts.filter(platform=platform)
            
        # Apply search filter
        if search_query:
            posts = posts.filter(
                Q(title__icontains=search_query) |
                Q(link__icontains=search_query) |
                Q(platform__icontains=search_query) |
                Q(user_id__username__icontains=search_query)
            )

        # Filter by date range
        if start_date and end_date:
            try:
                start_date = datetime.strptime(start_date, "%Y-%m-%d")
                end_date = datetime.strptime(end_date, "%Y-%m-%d")
                posts = posts.filter(publish_date__date__range=[start_date, end_date])
            except ValueError:
                return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Apply sorting
        if order == 'asc':
            posts = posts.order_by('publish_date')
        else:
            posts = posts.order_by('-publish_date')
       
        # Paginate results
        paginator = CustomLimitOffsetPagination()
        result_page = paginator.paginate_queryset(posts, request)
        
        serializer = self.get_serializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=False, methods=['POST'])
    def add_post(self, request):
        """
        Add a new social media post record.
        """
        data = request.data.copy()
        
        # Validate the platform is one of the supported ones
        platform = data.get('platform')
        supported_platforms = [choice[0] for choice in SocialMedia.PLATFORM_CHOICES]
        
        if platform and platform.lower() not in supported_platforms:
            return Response(
                {"error": f"Unsupported platform. Choose from: {', '.join(supported_platforms)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            post = serializer.save()
            return Response(self.get_serializer(post).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



    @action(detail=True, methods=['PATCH'])
    def update_post(self, request, pk=None):
        """
        Update an existing social media post.
        """
        try:
            post = SocialMedia.objects.get(pk=pk)
        except SocialMedia.DoesNotExist:
            return Response({"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(post, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




    @action(detail=False, methods=['GET'])
    def platform_summary(self, request):
        """
        Get summary statistics for each platform.
        """
        # Filter by date range if provided
        start_date = request.query_params.get('start_date', None)
        end_date = request.query_params.get('end_date', None)
        
        queryset = self.get_queryset()
        
        if start_date and end_date:
            try:
                start_date = datetime.strptime(start_date, "%Y-%m-%d")
                end_date = datetime.strptime(end_date, "%Y-%m-%d")
                queryset = queryset.filter(publish_date__date__range=[start_date, end_date])
            except ValueError:
                return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get counts by platform
        platform_stats = (
            queryset
            .values('platform')
            .annotate(
                post_count=Count('id'),
                latest_post_date=Max('publish_date')
            )
            .order_by('-post_count')
        )
        
        return Response(platform_stats, status=status.HTTP_200_OK)    

class UserParameterViewSet(viewsets.ModelViewSet):
    serializer_class = UserParameterSerializer
    permission_classes = [permissions.IsAuthenticated,IsSuperAdminOrAdminOrAssigned]

    def get_queryset(self):
        # Restrict the queryset to the authenticated user's parameters
        user_id = self.request.query_params.get('user_id')
        if user_id:
            return UserParameter.objects.filter(user_id=user_id)
        return UserParameter.objects.none()

    
    @action(detail=False, methods=['POST'])
    def add_parameter(self, request):
        """
        Add a new parameter for a user. 
        Admins can add parameters for any user. Regular users can only add their own parameters.
        """
        try:
            # Validate and fetch the user
            try:
                user = User.objects.get(id=request.data.get('user_id'))
            except User.DoesNotExist:
                raise NotFound(detail="User not found.")
            
            # Check permissions (ensures admin or self)
            self.check_object_permissions(request, user)

            # Extract data from the request
            number_of_posts = request.data.get("number_of_posts", 0)
            word_count = request.data.get("word_count", 0)
            subcategory_ids = request.data.get("subcategories", [])  # List of subcategory IDs

            # Validate subcategories
            subcategories = SubCategory.objects.filter(id__in=subcategory_ids)
            if not subcategories.exists():
                return Response({"error": "Invalid subcategory IDs."}, status=status.HTTP_400_BAD_REQUEST)

            # Create the UserParameter instance
            user_parameter = UserParameter.objects.create(
                user=user,
                number_of_posts=number_of_posts,
                word_count=word_count,
            )

            # Associate the selected subcategories
            user_parameter.subcategories.set(subcategories)

            # Serialize and return the created instance
            serializer = self.get_serializer(user_parameter)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            # Return error response
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['GET'])
    def get_parameter(self, request):
        # Retrieve the parameter for the requested user
        user_id = request.query_params.get('user_id', None)
        if not user_id:
            return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            instance = UserParameter.objects.get(user_id=user_id)
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        except UserParameter.DoesNotExist:
            return Response({}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['GET'])
    def list_parameters(self, request):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


    @action(detail=True, methods=['PATCH'])
    def update_parameter(self, request, pk=None):
        """
        Partially update a specific user parameter.
        Prevent changing the user_id.
        """
        try:
            # Fetch the UserParameter instance by primary key
            instance = UserParameter.objects.get(id=pk)
            
            # Check permissions to ensure the user is authorized to update this parameter
            self.check_object_permissions(request, instance.user)

            # Make a copy of the request data
            data = request.data.copy()

            # Ensure user_id cannot be updated
            if 'user_id' in data:
                del data['user_id']

            # Handle subcategories if provided
            subcategory_ids = data.pop('subcategories', None)  # Extract subcategory IDs from the request
            if subcategory_ids is not None:
                # Validate subcategories
                subcategories = SubCategory.objects.filter(id__in=subcategory_ids)
                if not subcategories.exists():
                    return Response({"error": "Invalid subcategory IDs."}, status=status.HTTP_400_BAD_REQUEST)
                # Associate the selected subcategories with the instance
                instance.subcategories.set(subcategories)

            # Partially update the instance with the provided data
            serializer = self.serializer_class(instance, data=data, partial=True)
            if serializer.is_valid():
                try:
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response(
                        {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UserParameter.DoesNotExist:
            return Response({"error": "UserParameter not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['POST', 'PATCH'])
    def update_or_add_parameter(self, request):
        """
        Add or update a user parameter.
        - For POST: Create a new parameter or update if it already exists.
        - For PATCH: Partially update an existing parameter.
        """
        try:
            # Validate and fetch the user
            user_id = request.data.get('user_id')
            if not user_id:
                return Response({"error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

            user = get_object_or_404(User, id=user_id)

            # Check permissions (ensures admin or self)
            self.check_object_permissions(request, user)

            # Extract data from the request
            data = request.data.copy()

            # Handle subcategories if provided
            subcategory_ids = data.pop('subcategories', None)  # Extract subcategory IDs from the request
            if subcategory_ids is not None:
                # Validate subcategories
                subcategories = SubCategory.objects.filter(id__in=subcategory_ids)
                if not subcategories.exists():
                    return Response({"error": "Invalid subcategory IDs."}, status=status.HTTP_400_BAD_REQUEST)

            # Use update_or_create to either update or create the UserParameter
            user_parameter, created = UserParameter.objects.update_or_create(
                user=user,
                defaults={
                    "number_of_posts": data.get("number_of_posts", 0),
                    "word_count": data.get("word_count", 0),
                }
            )

            # Associate the selected subcategories if provided
            if subcategory_ids is not None:
                user_parameter.subcategories.set(subcategories)

            # Serialize and return the instance
            serializer = self.get_serializer(user_parameter)
            if created:
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            # Return error response
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['DELETE'])
    def delete_parameter(self, request, pk=None):
        instance = self.get_object()
        try:
            instance.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CategoryViewSet(viewsets.ModelViewSet):
    """
    A ViewSet for managing categories and their associated subcategories.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    @action(detail=True, methods=['GET'])
    def subcategories(self, request, pk=None):
        """
        Retrieve all subcategories for a specific category.
        """
        try:
            category = Category.objects.get(pk=pk)
            subcategories = category.subcategories.all()
            serializer = SubCategorySerializer(subcategories, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Category.DoesNotExist:
            return Response({"error": "Category not found."}, status=status.HTTP_404_NOT_FOUND)
        
    @action(detail=False, methods=['GET'])
    def all_categories_with_subcategories(self, request):
        """
        Retrieve all categories along with their subcategories.
        """
        categories = Category.objects.prefetch_related('subcategories').all()
        serializer = self.get_serializer(categories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['POST'])
    def add_category_with_subcategories(self, request):
        """
        Add a new category along with its subcategories.
        """
        category_name = request.data.get('name')
        subcategories = request.data.get('subcategories', [])

        if not category_name:
            return Response({"error": "Category name is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            category = Category.objects.create(name=category_name)
            for subcategory_name in subcategories:
                SubCategory.objects.create(category=category, name=subcategory_name)

            serializer = self.get_serializer(category)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['PATCH'])
    def update_category_with_subcategories(self, request, pk=None):
        """
        Update a category and its subcategories while preserving existing IDs.
        """
        try:
            category = Category.objects.get(pk=pk)
            # Update category name if provided
            if 'name' in request.data:
                category.name = request.data['name']
                category.save()

            # Handle subcategories update
            if 'subcategories' in request.data:
                new_subcategories = request.data['subcategories']
                existing_subcategories = {sub.id: sub for sub in category.subcategories.all()}
                
                # Track which subcategories to keep
                subcategories_to_keep = set()
                
                for subcategory_data in new_subcategories:
                    if 'id' in subcategory_data:
                        # Update existing subcategory
                        sub_id = subcategory_data['id']
                        if sub_id in existing_subcategories:
                            existing_sub = existing_subcategories[sub_id]
                            existing_sub.name = subcategory_data['name']
                            existing_sub.save()
                            subcategories_to_keep.add(sub_id)
                    else:
                        # Create new subcategory
                        SubCategory.objects.create(
                            category=category,
                            name=subcategory_data['name']
                        )

                # Delete subcategories that are no longer in the list
                subcategories_to_delete = set(existing_subcategories.keys()) - subcategories_to_keep
                category.subcategories.filter(id__in=subcategories_to_delete).delete()

            serializer = self.get_serializer(category)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Category.DoesNotExist:
            return Response(
                {"error": "Category not found."}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['DELETE'])
    def delete_category_with_subcategories(self, request, pk=None):
        """
        Delete a category along with its subcategories.
        """
        try:
            category = Category.objects.get(pk=pk)
            category.delete()
            return Response({"message": "Category and its subcategories deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Category.DoesNotExist:
            return Response({"error": "Category not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 



class FeatureToggleViewSet(viewsets.ModelViewSet):
    """
    A ViewSet for managing feature toggles.
    """
    permission_classes = [IsAuthenticated]
    queryset = Feature.objects.all()
    serializer_class = FeatureSerializer

    def get_queryset(self):
        """
        Optionally restrict the returned features to those that are enabled.
        """
        return Feature.objects.all()

    @action(detail=False, methods=['GET'])
    def list_features(self, request):
        """
        List all features and their current status.
        """
        features = self.get_queryset()
        data = [{"name": feature.name, "is_enabled": feature.is_enabled} for feature in features]
        return Response({'features': data})

    @action(detail=False, methods=['PATCH'])
    def toggle_feature(self, request):
        """
        Toggle the status of a specific feature.
        - action: 'on' to enable, 'off' to disable.
        """
        feature_name = request.data.get('feature_name')
        is_enabled = request.data.get('is_enabled')  # 'on' or 'off'
        
        try:
            feature = Feature.objects.get(name=feature_name)
            feature.is_enabled = is_enabled
            feature.save()
            return Response({'message': f'Feature {feature_name} toggled successfully'})
        except Feature.DoesNotExist:
            return Response({'message': 'Feature not found'}, status=status.HTTP_404_NOT_FOUND)
        
    
    @action(detail=False, methods=['POST'])
    def add_feature(self, request):
        """
        Add a new feature.
        """
        name = request.data.get('feature_name')
        is_enabled = request.data.get('is_enabled', False)

        if not name:
            return Response({'message': 'Feature name is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the feature already exists
        if Feature.objects.filter(name=name).exists():
            return Response({'message': 'Feature already exists'}, status=status.HTTP_400_BAD_REQUEST)

        feature = Feature.objects.create(name=name, is_enabled=is_enabled)
        return Response({'message': f'Feature {name} added successfully', 'id': feature.id})




class SuperAdminViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        if self.action == 'assign_clients':
            return [permissions.IsAuthenticated(), IsSuperAdmin()]
        if self.action == 'list_clients':
            return [permissions.IsAuthenticated(),IsSuperAdmin()]
        if self.action == 'view_client':
            return [permissions.IsAuthenticated(), IsAdminOrSelf()]
        if self.action == 'update_client':
            return [permissions.IsAuthenticated(), IsAdminOrSelf()]
        if self.action == 'delete_client':
            return [permissions.IsAuthenticated(), IsAdminOrSelf()]
        return super().get_permissions()

    @action(detail=False, methods=['POST'])
    def assign_clients(self, request, *args, **kwargs):
        """
        Assign multiple clients to a specific admin.
        """
        admin_id = request.data.get('admin_id')
        client_ids = request.data.get('client_ids')

        if not admin_id or not client_ids:
            return Response({"error": "Admin ID and Client IDs are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            admin = User.objects.get(id=admin_id, role='Admin')
        except User.DoesNotExist:
            return Response({"error": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)

        clients = User.objects.filter(id__in=client_ids, role='User')

        if not clients:
            return Response({"error": "No valid clients found."}, status=status.HTTP_404_NOT_FOUND)

        # Assign clients to the admin
        clients.update(assigned_admin=admin)

        return Response({"message": f"{len(clients)} clients have been assigned to admin {admin.email}."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['GET'])
    def list_clients(self, request, *args, **kwargs):
        """
        List all clients.
        """
        clients = User.objects.filter(role='User')

        serializer = UserSerializer(clients, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['GET'])
    def view_client(self, request, pk=None, *args, **kwargs):
        """
        View details of a specific client.
        """
        try:
            client = User.objects.get(id=pk, role='User')
        except User.DoesNotExist:
            return Response({"error": "Client not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(client)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['PUT'])
    def update_client(self, request, pk=None, *args, **kwargs):
        """
        Update details of a specific client.
        """
        try:
            client = User.objects.get(id=pk, role='User')
        except User.DoesNotExist:
            return Response({"error": "Client not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(client, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Client details updated."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['DELETE'])
    def delete_client(self, request, pk=None, *args, **kwargs):
        """
        Delete a specific client.
        """
        try:
            client = User.objects.get(id=pk, role='User')
        except User.DoesNotExist:
            return Response({"error": "Client not found."}, status=status.HTTP_404_NOT_FOUND)

        client.delete()
        return Response({"message": "Client deleted."}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['GET'])
    def clients_by_admin(self, request, *args, **kwargs):
        # Get the admin_id from URL parameters
        admin_id = kwargs.get('admin_id')
        
        try:
            # Get the admin user object
            admin_user = User.objects.get(id=admin_id, role='Admin')
        except User.DoesNotExist:
            return Response({"error": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)
        
        # Filter clients assigned to this admin
        clients = User.objects.filter(assigned_admin=admin_user)
        
        # Serialize the client data
        client_data = [
            {
                "id": client.id,
                "name": client.name,
                "email": client.email,
                "role": client.role,
                "company_name": client.company_name,
                "phone": client.phone,
                "status": client.status
            } for client in clients
        ]
        
        return Response(client_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['GET'])
    def admins(self, request, *args, **kwargs):
        # Filter users with the role of 'Admin'
        admins = User.objects.filter(role='Admin')
        
        # Serialize the admin data
        admin_data = [
            {
                "id": admin.id,
                "name": admin.name,
                "email": admin.email,
                "role": admin.role,
                "company_name": admin.company_name,
                "phone": admin.phone,
                "status": admin.status
            } for admin in admins
        ]
        
        return Response(admin_data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['GET'])
    def clients_grouped_by_admin(self, request, *args, **kwargs):
        """
        Distinguish clients by whether they are assigned to an admin or not.
        """
        # Get all clients
        assigned_clients = User.objects.filter(role='User', assigned_admin__isnull=False)
        unassigned_clients = User.objects.filter(role='User', assigned_admin__isnull=True)

        # Serialize the data
        data = {
            "assigned_clients": [
                {
                    "id": client.id,
                    "name": client.name,
                    "email": client.email,
                    "assigned_admin_id": client.assigned_admin.id,
                    "assigned_admin_email": client.assigned_admin.email
                } for client in assigned_clients
            ],
            "unassigned_clients": [
                {
                    "id": client.id,
                    "name": client.name,
                    "email": client.email
                } for client in unassigned_clients
            ]
        }

        return Response(data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['POST'])
    def add_user(self, request, *args, **kwargs):
        data = request.data
        email = data.get('email')
        name = data.get('name')
        role = data.get('role', 'User')
        company_name = data.get('company_name')
        phone = data.get('phone')

        if not email or not name:
            return Response({"error": "Email and name are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Create user
        user = User.objects.create(
            username=email,
            email=email,
            name=name,
            role=role,
            company_name=company_name,
            phone=phone,
            is_active=False  # Initially inactive
        )

        # If the role is not Admin, create a Stripe customer
        if role != 'Admin':
            stripe_customer = stripe.Customer.create(
                email=user.email,
                metadata={"user_id": user.id}
            )
            user.stripe_customer_id = stripe_customer['id']

        user.save()

        # Generate password setup link
        token = PasswordResetTokenGenerator().make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        frontend_base_url = f"{settings.FRONTEND_BASE_URL}/login/reset-password"
        password_setup_url = f"{frontend_base_url}/{uidb64}/{token}"

        try:
            send_mail(
                subject="Set Your Password",
                message=f"Click the link to set your password: {password_setup_url}",
                from_email='django@demomailtrap.com',
                recipient_list=[email],
            )
        except Exception as e:
            return Response({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "User added successfully and email sent."}, status=status.HTTP_201_CREATED)
    


class CustomBlogTopicViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing CustomBlogTopic.
    Only Admin and SuperAdmin can access these endpoints.
    """
    queryset = CustomBlogTopic.objects.all()
    serializer_class = CustomBlogTopicSerializer
    permission_classes = [IsSuperAdminOrAdmin]

    @action(detail=False, methods=['POST'])
    def add_topic(self, request):
        """
        Add a new custom blog topic with max 3 topics per date validation.
        """
        try:
            data = request.data.copy()
            
            # Validate required fields
            required_fields = ['title', 'usage_date', 'user', 'primary_keyword']
            for field in required_fields:
                if field not in data:
                    return Response(
                        {"error": f"{field} is required."}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Check if max topics limit reached
            usage_date = data['usage_date']
            user_id = data['user']
            
            existing_topics = CustomBlogTopic.objects.filter(
                usage_date=usage_date,
                user_id=user_id
            ).count()

            if existing_topics >= 3:
                return Response(
                    {
                        "error": f"Maximum 3 topics are allowed per date. You already have {existing_topics} topics for {usage_date}"
                    }, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = self.get_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    
    @action(detail=False, methods=['GET'])
    def list_topics(self, request):
        """
        List all custom blog topics with filtering and search.
        Supports filtering by:
        - user_id
        - usage_date (exact date match)
        - date range (start_date and end_date)
        - search terms
        - keywords
        """
        try:
            # Get query parameters
            user_id = request.query_params.get('user_id')
            usage_date = request.query_params.get('usage_date')  # Add specific date filter
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            search = request.query_params.get('search', '').strip()
            keyword = request.query_params.get('keyword', '').strip()

            # Base queryset
            queryset = self.get_queryset().order_by('-usage_date')

            # Apply user filter
            if user_id:
                queryset = queryset.filter(user_id=user_id)
            
            # Apply specific date filter
            if usage_date:
                try:
                    specific_date = datetime.strptime(usage_date.strip('"'), '%Y-%m-%d').date()
                    queryset = queryset.filter(usage_date=specific_date)
                except ValueError:
                    return Response(
                        {"error": "Invalid usage_date format. Use YYYY-MM-DD"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            # Apply date range filter if no specific date is provided
            elif start_date or end_date:
                date_filters = {}
                if start_date:
                    try:
                        date_filters['usage_date__gte'] = datetime.strptime(start_date, '%Y-%m-%d').date()
                    except ValueError:
                        return Response(
                            {"error": "Invalid start_date format. Use YYYY-MM-DD"}, 
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                if end_date:
                    try:
                        date_filters['usage_date__lte'] = datetime.strptime(end_date, '%Y-%m-%d').date()
                    except ValueError:
                        return Response(
                            {"error": "Invalid end_date format. Use YYYY-MM-DD"}, 
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                queryset = queryset.filter(**date_filters)

            # Search in title and keywords
            if search:
                queryset = queryset.filter(
                    Q(title__icontains=search) |
                    Q(primary_keyword__icontains=search) |
                    Q(secondary_keyword__icontains=search)
                )

            # Specific keyword search
            if keyword:
                queryset = queryset.filter(
                    Q(primary_keyword__icontains=keyword) |
                    Q(secondary_keyword__icontains=keyword)
                )

            paginator = CustomLimitOffsetPagination()
            result_page = paginator.paginate_queryset(queryset, request)
            serializer = self.get_serializer(result_page, many=True)
            
            return paginator.get_paginated_response(serializer.data)

        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['GET'])
    def get_topic(self, request, pk=None):
        """
        Retrieve a specific custom blog topic.
        """
        try:
            topic = self.get_object()
            serializer = self.get_serializer(topic)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except CustomBlogTopic.DoesNotExist:
            return Response(
                {"error": "Topic not found."}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['PATCH'])
    def update_topic(self, request, pk=None):
        """
        Update a specific custom blog topic with max 3 topics per date validation.
        """
        try:
            topic = self.get_object()
            data = request.data.copy()

            # If usage_date is being updated, check the limit
            if 'usage_date' in data:
                existing_topics = CustomBlogTopic.objects.filter(
                    usage_date=data['usage_date'],
                    user=topic.user
                ).exclude(pk=topic.pk).count()

                if existing_topics >= 3:
                    return Response(
                        {
                            "error": f"Maximum 3 topics are allowed per date. Already have {existing_topics} topics for {data['usage_date']}"
                        }, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

            serializer = self.get_serializer(
                topic, 
                data=data, 
                partial=True
            )
            
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except CustomBlogTopic.DoesNotExist:
            return Response(
                {"error": "Topic not found."}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['DELETE'])
    def delete_topic(self, request, pk=None):
        """
        Delete a specific custom blog topic.
        """
        try:
            topic = self.get_object()
            topic.delete()
            return Response(
                {"message": "Topic deleted successfully."}, 
                status=status.HTTP_204_NO_CONTENT
            )
        except CustomBlogTopic.DoesNotExist:
            return Response(
                {"error": "Topic not found."}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserGeneratedTopicViewSet(viewsets.ModelViewSet):
    """
    A ViewSet for managing UserGeneratedTopic CRUD operations.
    """
    queryset = UserGeneratedTopic.objects.all()
    serializer_class = UserGeneratedTopicSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        Restrict the queryset to topics for the authenticated user.
        """
        return UserGeneratedTopic.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """
        Automatically associate the topic with the authenticated user during creation.
        """
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['POST'])
    def add_topics(self, request):
        """
        Add multiple topics for the authenticated user.
        """
        topics = request.data.get('topics', [])
        user=request.data.get('user',None)
        if not topics:
            return Response({"error": "No topics provided."}, status=status.HTTP_400_BAD_REQUEST)

        created_topics = []
        for topic_data in topics:
            serializer = self.get_serializer(data=topic_data)
            if serializer.is_valid():
                serializer.save()
                created_topics.append(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(created_topics, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['PATCH'])
    def update_topic(self, request, pk=None):
        """
        Update a specific topic for the specified user.
        """
        user_id = request.data.get('user', None)
        if not user_id:
            return Response({"error": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Validate that the user exists
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Validate that the topic exists and belongs to the specified user
            topic = UserGeneratedTopic.objects.get(pk=pk, user=user)
        except UserGeneratedTopic.DoesNotExist:
            return Response({"error": "Topic not found for the specified user."}, status=status.HTTP_404_NOT_FOUND)

        # Update the topic with the provided data
        serializer = self.get_serializer(topic, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['DELETE'])
    def delete_topic(self, request, pk=None):
        """
        Delete a specific topic for the authenticated user.
        """
        try:
            topic = UserGeneratedTopic.objects.get(pk=pk, user=request.user)
            topic.delete()
            return Response({"message": "Topic deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except UserGeneratedTopic.DoesNotExist:
            return Response({"error": "Topic not found."}, status=status.HTTP_404_NOT_FOUND)

    # @action(detail=False, methods=['GET'])
    # def get_topics(self, request):
    #     """
    #     Retrieve all topics for the specified user based on the user_id query parameter.
    #     """
    #     user_id = request.query_params.get('user_id', None)
    #     if not user_id:
    #         return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

    #     try:
    #         user = User.objects.get(id=user_id)
    #     except User.DoesNotExist:
    #         return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    #     topics = UserGeneratedTopic.objects.filter(user=user)
    #     serializer = self.get_serializer(topics, many=True)
    #     return Response(serializer.data, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['GET'])
    def get_topics(self, request):
        """
        Retrieve the latest 10 topic titles for the specified user based on the user_id query parameter.
        """
        user_id = request.query_params.get('user_id', None)
        if not user_id:
            return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        topics = UserGeneratedTopic.objects.filter(user=user).order_by('-created_at')[:10]
        topic_titles = [topic.title for topic in topics]

        return Response({'latest_topics': topic_titles}, status=status.HTTP_200_OK)

    



class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer

 
    @action(detail=False, methods=['GET'])
    def list_reviews(self, request):
        """
        API to get reviews by the authenticated user.
        
        """
        user_id = request.query_params.get('user_id', None)
        if not user_id:
            return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        reviews = Review.objects.filter(user=user)
        serializer = self.get_serializer(reviews, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['GET'])
    def download_sample_csv(self, request):
        """
        API to download a sample CSV file with the required fields.
        """
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="sample_reviews.csv"'

        writer = csv.writer(response)
        writer.writerow(['name', 'number', 'email', 'review', 'rating'])  # Header row
        writer.writerow(['John Doe', '1234567890', 'johndoe@example.com', 'Great service!', '5'])  # Sample data

        return response

    @action(detail=False, methods=['POST'])
    def upload_csv(self, request):
        """
        API to upload a CSV file and save the data into the database.
        """
        file = request.FILES.get('file')
        if not file:
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        user_id = request.data.get('user_id', None)
        if not user_id:
            return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        try:
            decoded_file = file.read().decode('utf-8').splitlines()
            reader = csv.DictReader(decoded_file)
            reviews = []
            for row in reader:
                review_data = {
                    "user": user.id,
                    "name": row['name'],
                    "number": row['number'],
                    "email": row['email'],
                    "review": row['review'],
                    "rating": int(row['rating'])  # ✅ Ensure rating is an int
                }
                serializer =  ReviewSerializer(data=review_data)
                if serializer.is_valid():
                    reviews.append(serializer.save())
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": f"{len(reviews)} reviews uploaded successfully."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": "Invelid csv file ."}, status=status.HTTP_400_BAD_REQUEST)



