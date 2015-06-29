**How does GAIL work?**

GAIL uses [Google Apps' Single-Sign On](http://code.google.com/apis/apps/sso/saml_reference_implementation.html) support to give administrators better control over their user's login experience.  GAIL is designed to run on [Google's App Engine](http://appengine.google.com) so it does not require the administrator to set up their own web server.

**Do I have to recreate my user accounts or reset their passwords once I setup GAIL?**

No, GAIL uses your existing users and passwords by authenticating against your Google Apps Domain behind the scenes.  Users will continue to use their same username and password.

**How can Admins log in as users with GAIL?**

Anyone who is an administrator for the Google Apps Domain can log in as another user by specifying their username as `<adminuser>+<loginuser>` where `<adminuser>` is the administrator's username and `<loginuser>` is the user the admin wishes to login as (e.g. admin+enduser).  The admin should use their own password.  GAIL will verify that the admin's username and password is correct and if it is, they will be logged in as the end user.

**How can Users log in as other users with GAIL?**

GAIL can be configured to give non-admin users access to other user accounts (for example, a teacher could be given access to log in as their students).  GAIL uses group membership to determine who can login as who.  Let's look at an example.  John Jones (jjones@example.com) is a student in James Smith's (jsmith@example.com) 8th grade class.  If you want to give jsmith rights to login as jjones, you could create a Google Apps group names jjones-become and add jsmith as a member.  Or, if everyone in jsmith's class is a member of the group Grade8, you could create a group named Grade8-become and add jsmith to the group. To login as jjones, jsmith would specify his username as jsmith+jjones just like the Admin login feature above.  **Be aware that currently, if you give a user rights to login as an admin account, they will be able to gain Admin access to Google Apps!**  A future version will have a setting that will always prevent users from logging in as Admins even if they are explicitly given rights to do so.

**How can I customize my login page?**

GAIL's default login page is extremely spartan for the simple reason that I am not a web designer.  You can customize the login page by editing the gail/templates/login.html file.  Be sure to leave the form intact and any python variable like {{ samlrequest }}.  If you wish to include other .css and .jpg files, place them in the gail/static folder and be sure to specify them in app.yaml.  See [the App Engine Docs](http://code.google.com/appengine/docs/python/tools/configuration.html) for information on app.yaml.

**Help! GAIL was working fine but now users only get a blank screen after login!**

If you are using GAIL 0.3a, the quick fix is to replace your utils.py with an [updated version of utils.py from SVN](http://google-apps-improved-login.googlecode.com/svn/trunk/gail/utils.py).  For more details on the problem, see [this post in the forum.](http://groups.google.com/group/google-apps-improved-login/browse_thread/thread/bcb65dcd50bc6b1a?hl=en#)