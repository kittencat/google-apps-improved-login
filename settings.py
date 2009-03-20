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
