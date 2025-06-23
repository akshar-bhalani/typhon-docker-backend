"""
URL configuration for Typhon project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from api.views import BlogSettingViewSet, BlogViewSet, CategoryViewSet, DashboardViewset, FeatureToggleViewSet, PaymentViewSet, ReviewViewSet, StripeViewSet, SubscriptionPlanViewSet, UserGeneratedTopicViewSet, UserParameterViewSet, UserViewSet, WordPressViewSet,SuperAdminViewSet,SocialMediaViewSet,CustomBlogTopicViewSet
from django.contrib import admin

# Create a router and register the AuthViewSet
router = DefaultRouter()
# router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'^api/v1/users', UserViewSet, basename='user')
router.register(r'^api/v1/blogsettingviewset', BlogSettingViewSet, basename='blogsetting')
router.register(r'^api/v1/wordpress', WordPressViewSet, basename='wordpress')
router.register(r'api/v1/subscription-plans', SubscriptionPlanViewSet, basename='subscriptionplan')
router.register(r'^api/v1/payments', PaymentViewSet, basename='payment')
router.register(r'^api/v1/blogs', BlogViewSet, basename='blog')
router.register(r'^api/v1/userparameter', UserParameterViewSet, basename='user-parameter')
router.register(r'^api/v1/stripe', StripeViewSet, basename='stripe')
router.register(r'^api/v1/superadmin', SuperAdminViewSet, basename='admin')
router.register(r'^api/v1/dashboard', DashboardViewset, basename='dashboard')
router.register(r'^api/v1/feature', FeatureToggleViewSet, basename='feature')
router.register(r'^api/v1/socialmedia', SocialMediaViewSet, basename='socialmedia')
router.register(r'^api/v1/categories', CategoryViewSet, basename='category')
router.register(r'^api/v1/generated-topics', UserGeneratedTopicViewSet, basename='generated-topics')
router.register(r'^api/v1/reviews', ReviewViewSet, basename='review')
router.register(r'^api/v1/custom-blog-topics', CustomBlogTopicViewSet, basename='custom-blog-topics')

urlpatterns = [
    path('api/v1/categories/subcategories/<int:pk>/', CategoryViewSet.as_view({'get': 'subcategories'}), name='category-subcategories'),
    path('api/v1/categories/update_category_with_subcategories/<int:pk>/', CategoryViewSet.as_view({'patch': 'update_category_with_subcategories'}), name='update-category-subcategories'),
    path('api/v1/categories/delete_category_with_subcategories/<int:pk>/', CategoryViewSet.as_view({'delete': 'delete_category_with_subcategories'}), name='delete-category-subcategories'),
    
    path('api/v1/users/get_user/<int:pk>',UserViewSet.as_view({'get': 'get_user'}), name='user-profile'),
    path('api/v1/users/update_user/<int:pk>',UserViewSet.as_view({'put': 'update_user'}), name='update-user'),
    path('api/v1/users/delete_user/<int:pk>',UserViewSet.as_view({'delete': 'delete_user'}), name='delete-user'),
    path('api/v1/users/password-setup/<str:uidb64>/<str:token>/', UserViewSet.as_view({'post': 'password_setup'}), name='password-setup'),

    path('api/v1/blogsettingviewset/update_blog_setting/<int:pk>',BlogSettingViewSet.as_view({'patch': 'update_blog_setting'}), name='update-blog-setting'),
    path('api/v1/blogsettingviewset/delete_blog_setting/<int:pk>',BlogSettingViewSet.as_view({'delete': 'delete_blog_setting'}), name='delete-blog-setting'),
    path('api/v1/blogsettingviewset/get_blog_setting/<int:pk>',BlogSettingViewSet.as_view({'get': 'get_blog_setting'}), name='get-blog-setting'),
    path('api/v1/blogsettingviewset/list_blog_setting/<int:pk>',BlogSettingViewSet.as_view({'get': 'list_blog_setting'}), name='list-blog-setting'),
    
    
    path('api/v1/wordpress/get_wordpress_setting/<int:pk>/', WordPressViewSet.as_view({'get': 'get_wordpress_setting'}), name='get-wordpress-setting'),
    path('api/v1/wordpress/update_wordpress_setting/<int:pk>/', WordPressViewSet.as_view({'patch': 'update_wordpress_setting'}), name='update-wordpress-setting'),
    path('api/v1/wordpress/delete_wordpress_setting/<int:pk>/', WordPressViewSet.as_view({'delete': 'delete_wordpress_setting'}), name='delete-wordpress-setting'),
    path('api/v1/wordpress/list_wordpress_settings/<int:pk>/', WordPressViewSet.as_view({'get': 'list_wordpress_settings'}), name='list-wordpress-setting'),
    

    path('api/v1/subscription-plans/get_subscription_plan/', SubscriptionPlanViewSet.as_view({'get': 'get_subscription_plan'}), name='get-subscription-plan'),
    path('api/v1/subscription-plans/update_subscription_plan/<int:pk>/', SubscriptionPlanViewSet.as_view({'patch': 'update_subscription_plan'}), name='update-subscription-plan'),
    path('api/v1/subscription-plans/delete_subscription_plan/<int:pk>/', SubscriptionPlanViewSet.as_view({'delete': 'delete_subscription_plan'}), name='delete-subscription-plan'),
    path('api/v1/subscription-plans/cancel_subscription/', SubscriptionPlanViewSet.as_view({'post': 'cancel_subscription'}), name='cancel-subscription-plan'),



    path('api/v1/socialmedia/add_post/', SocialMediaViewSet.as_view({'post': 'add_post'}), name='add-socialmedia-post'),
    path('api/v1/socialmedia/update_post/<int:pk>', SocialMediaViewSet.as_view({'patch': 'update_post'}), name='update-socialmedia-post'),

   
   

    path('api/v1/payments/get_user_payment', PaymentViewSet.as_view({'get': 'get_user_payment'}), name='get-user-payment'),
    # path('api/v1/payments/update_payment/<int:pk>', PaymentViewSet.as_view({'patch': 'update_payment'}), name='update-payment'),
    # path('api/v1/payments/delete_payment/<int:pk>', PaymentViewSet.as_view({'delete': 'delete_payment'}), name='delete-payment'),
    path('api/v1/payments/get_payment/<int:pk>', PaymentViewSet.as_view({'get': 'get_payment'}), name='get-payment'),

    path('api/v1/blogs/get_blog_from_wordpress/<int:pk>', BlogViewSet.as_view({'get': 'get_blog_from_wordpress'}), name='get-blog-wordpress'),
    path('api/v1/blogs/update_blog_to_wordpress/<int:pk>', BlogViewSet.as_view({'patch': 'update_blog_to_wordpress'}), name='update-blog-wordpress'),

   
    # path('api/v1/userparameter/get_parameter/<int:pk>', UserParameterViewSet.as_view({'get': 'get_parameter'}), name='get-parameter'),
    path('api/v1/userparameter/update_parameter/<int:pk>', UserParameterViewSet.as_view({'patch': 'update_parameter'}), name='update-parameter'),

    path('api/v1/generated-topics/update_topic/<int:pk>', UserGeneratedTopicViewSet.as_view({'patch': 'update_topic'}), name='update-topic'),

    path('api/v1/custom-blog-topics/get/<int:pk>',CustomBlogTopicViewSet.as_view({'get': 'get_topic'}),name='get-custom-blog-topic'),
    path('api/v1/custom-blog-topics/update/<int:pk>',CustomBlogTopicViewSet.as_view({'patch': 'update_topic'}),name='update-custom-blog-topic'),
    path('api/v1/custom-blog-topics/delete/<int:pk>',CustomBlogTopicViewSet.as_view({'delete': 'delete_topic'}),name='delete-custom-blog-topic'),


   
    path('api/v1/superadmin/clients/by-admin/<int:admin_id>/', SuperAdminViewSet.as_view({'get': 'clients_by_admin'}), name='clients-by-admin'),


    path('admin/', admin.site.urls),
   
    path('api/v1/', include('api.urls')),
]

urlpatterns += router.urls