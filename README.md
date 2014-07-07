vnc_angel
=========

Watch over servers that are encrypted using dm-crypt


With a vertulised server, you want as much security as possible.
You might want CentOS with SELinux, (come on, it isn't that hard.)
You might want full disk encryption, (dm-crypt).

Sounds good.. until the server is rebooted in the middle of the night.
Without dm-crypt everything comes back up on its own. So how do we
automate that? (Nagios / Cfengine)

If you use <a href="//github.com/alexxroche/Notice/">Notice</a> or
some other ISP in a box, to automate server instillation, then it is
a simple step to, (sudo) randomly marry servers together such that
they check on their spouse and enter the passphrase if the server
is stuck in boot.

Using Cfengine it is safe and easy to automate passphrase rolling.


To Do
=====

Change the on-screen mouse location to match the hour-hand
of an analogue clock. (Right now it just moves vertically.)
