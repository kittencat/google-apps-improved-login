# settings.py
#
# This file allows you to customize GAIL to fit your needs.  At most, you'll 
# need to edit GAPPS_DOMAIN and 

# GAPPS_DOMAIN - Your Google Apps Domain.  If your Google Apps email address is 
# jdoe@example.com, then this would be example.com
# defaults to None since it must be set by each admin.

#GAPPS_DOMAIN = 'example.com'
GAPPS_DOMAIN = 'example.com'

# ADMINS_BECOME_USER - If this setting is true, then user who is marked as an
# Administrator in your Google Apps dashboard will be able to log in as any 
# other user.  The Administrator will enter <admin>+<becomeuser> as the username
# (where <admin> is the Administrator's username and <becomeuser> is the user
# they want to log in as).  The Administrator will use their own password. Note 
# that True and False are case sensitive in Python.  Be sure to capitalize 
# *only* the first letter

#ADMINS_BECOME_USER = False
ADMINS_BECOME_USER = True

# USERS_BECOME_USERS - If this settings is true and a valid Admin username and
# password are set for ADMIN_USER and ADMIN_PASS, then you can assign regular
# users the ability to login as other users.  Who is able to login as who is
# determined by group membership.  So if you want the user MrSmith to be able
# to log in as the user John, create a group in your Google Apps Dashboard
# named John-Become and add MrSmith to the group.  If you want MrSmith to be
# able to log in as John, Mary and George, add John, Mary and George ti the
# group SixthGrade and add MrSmith to the group SixthGrade-Become.

#USERS_BECOME_USERS = True
USERS_BECOME_USERS = False

# ADMIN_USER - The name of an account that is an admin of the Google Apps Domain
# this account is used to lookup group membership for the USERS_BECOME_USERS
# setting.  If USERS_BECOME_USERS is False, you do not need to set ADMIN_USER

#ADMIN_USER = 'admin'
ADMIN_USER = ''

# ADMIN_PASS - The password of an account that is an admin of the Google Apps 
# Domain this account is used to lookup group membership for the 
# USERS_BECOME_USERS setting.  If USERS_BECOME_USERS is False, you do not need
# to set ADMIN_PASS

#ADMIN_PASS = 'p@ssw0rd'
ADMIN_USER = ''