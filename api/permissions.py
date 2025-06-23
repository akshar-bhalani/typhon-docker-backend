

from rest_framework import permissions
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from .models import User


class IsAdminUser(BasePermission):
    """
    Custom permission to allow only admin users based on Token authentication.
    """

    def has_permission(self, request, view):
        # Extract the token from the Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Token '):
            self.message = {"detail": "No valid token provided."}
            return False

        token = auth_header.split(' ')[1]  # Extract the token value
        try:
            # Authenticate the token
            user, token_obj = TokenAuthentication().authenticate_credentials(token)
            
            # Check the user's role
            if getattr(user, 'role', None) != 'Admin':  # Replace 'role' with your actual field name
                self.message = {"detail": "The current user is not an admin."}
                return False
            
            # Attach the authenticated user to the request
            request.user = user
        except AuthenticationFailed as e:
            self.message = {"detail": str(e)}
            return False

        return True

class IsAdminOrSelf(BasePermission):
    """
    Custom permission to allow admins to update any user profile
    and normal users to update only their own profile,
    based on the token provided in the Authorization header.
    """
    
    def has_object_permission(self, request, view,obj):
        # Extract the token from the Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Token '):
            self.message = {"detail": "No valid token provided."}
            return False

        token = auth_header.split(' ')[1]  # Extract the token value
        try:
            # Authenticate the token
            user, token_obj = TokenAuthentication().authenticate_credentials(token)
            

         
            
            if getattr(user, 'role', None) == 'Admin':  # Replace 'role' with your actual field name
                
                return True
            elif getattr(user,'id',None)==obj.id:
                return True

        except AuthenticationFailed as e:
            self.message = {"detail": str(e)}
            return False

        # Deny permission for all other cases
        return False



class IsActiveUser(permissions.BasePermission):
    """
    Custom permission to only allow active users to access the view.
    """
    def has_permission(self, request, view):
        # Allow only active users
        return request.user and request.user.status == 'active'







class IsSuperAdmin(permissions.BasePermission):
    """
    Allows access only to super admin users.
    """
    def has_permission(self, request, view):
        return request.user.role == 'SuperAdmin'

class IsSuperAdminOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'SuperAdmin' or request.user.role == 'Admin'


class IsAdminOrAssigned(permissions.BasePermission):
    """
    Allows access to admin users only if they are assigned to the user.
    """
    def has_permission(self, request, view):
        if request.user.role == 'Admin':
            # Check if the user is assigned to the admin
            user_id = view.kwargs.get('pk')
            if user_id:
                try:
                    user = User.objects.get(id=user_id)
                    return user.assigned_admin == request.user
                except User.DoesNotExist:
                    return False
        return False


class IsSuperAdminOrAdminOrAssigned(permissions.BasePermission):
    """
    Allows access based on role:
    - Super Admin: Full access.
    - Admin: Access only to assigned users.
    - Normal User: Access only to their own data.
    """

    def has_permission(self, request, view):
        user = request.user

        # Super Admin has full access
        if user.role == 'SuperAdmin':
            return True

        user_id = view.kwargs.get('pk') or request.data.get('user_id') or request.query_params.get('user_id')
        # Admin can access their assigned users
        if user.role == 'Admin' and user_id:
            if str(user.id) == str(user_id):  # Allow Admin to access their own profile
                return True
            assigned_user = User.objects.filter(id=user_id, assigned_admin=user).first()
            return assigned_user is not None  # True if the user exists and is assigned to this admin

        # Normal users can only access their own data
        if user.role == 'User' and user_id:
            return str(user.id) == str(user_id)

        return False

    def has_object_permission(self, request, view, obj):
        user = request.user

        # Super Admin has full access
        if user.role == 'SuperAdmin':
            return True

        # Admin can access only their assigned users and their own profile
        if user.role == 'Admin':
            if obj.id == user.id:  # Allow Admin to update their own profile
                return True
            return hasattr(obj, 'assigned_admin') and obj.assigned_admin == user

        # Normal users can only access their own data
        if obj.id == user.id:
            return True

        return False


# class IsSuperAdminOrAdmin(permissions.BasePermission):
#     """
#     - Super Admin: Full access.
#     - Admin: Only access their assigned users.
#     """

#     def has_permission(self, request, view):
#         user = request.user
#         print("iam alos shdkgjdh")
#         # Super Admin has full access
#         if user.role == 'SuperAdmin':
#             return True

#         # Admin can only access assigned users
#         if user.role == 'Admin':
#             print("i am here")
#             user_id = view.kwargs.get('pk') or request.data.get('user_id')
#             if user_id:
#                 return User.objects.filter(id=user_id, assigned_admin=user).exists()

#         return False

#     def has_object_permission(self, request, view, obj):
#         user = request.user

#         # Super Admin has full access
#         if user.role == 'SuperAdmin':
#             return True

#         # Admin can only access assigned users
#         if user.role == 'Admin' and hasattr(obj, 'assigned_admin'):
#             return obj.assigned_admin == user

#         return False

class WordPressPermission(permissions.BasePermission):
    """
    Custom permission to allow access based on user role for WordPress instances.
    """

    def has_object_permission(self, request, view, obj):
        """
        Check permissions for a specific WordPress instance.
        - SuperAdmin: Access to all WordPress instances.
        - Admin: Access to WordPress instances assigned to them or created by them.
        - Regular User: Access only to their own WordPress instance.
        """

        # print("obj is",obj.user)

        # SuperAdmin: Can access any WordPress instance
        if request.user.role == 'SuperAdmin':
            return True
        
        # Admin: Can access WordPress instances where they are assigned as admin or created by them
        if request.user.role == 'Admin':
            if obj.user == request.user or obj.user.assigned_admin == request.user:
                return True

        # Regular User: Can only access their own WordPress instance
        if obj.user == request.user:
            return True
        
        return False

class BlogSettingPermission(permissions.BasePermission):
    """
    Custom permission to allow access based on user role for WordPress instances.
    """

    def has_object_permission(self, request, view, obj):
        """
        Check permissions for a specific WordPress instance.
        - SuperAdmin: Access to all WordPress instances.
        - Admin: Access to WordPress instances assigned to them or created by them.
        - Regular User: Access only to their own WordPress instance.
        """

        # SuperAdmin: Can access any WordPress instance
        if request.user.role == 'SuperAdmin':
            return True
        
        # Admin: Can access WordPress instances where they are assigned as admin or created by them
        if request.user.role == 'Admin':
            if obj.user_id == request.user or obj.user_id.assigned_admin == request.user:
                return True

        # Regular User: Can only access their own WordPress instance
        if obj.user_id == request.user:
            return True
        
        return False