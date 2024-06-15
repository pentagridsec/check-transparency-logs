Introduction
=============

This directory contains check scripts to monitor certificates of your infrastructure with the aim of finding
forged certificates. Forging certificates should be prevented in the first place. Therefor, using CAA DNS records in combination
with ``accounturi`` property is recommended. It may not cover all situations, especially in the event of a rogue CA.

The monitoring approach is two-fold: The external scan script ``check_ct_remote.py`` checks a service's
certificate that a server offers and looks it up in transparency logs. An internal check script ``check_ct_local.py``
checks if there is a discrepancy between certificate logs and certificates which are known to be issued to a host/service, because they
are used on a server. This local check is not necessarily run on a server. It can be run anywhere, where a copy of the
server certificate(s) is present.

The entire story and background is explained in our blog post at: https://www.pentagrid.ch/en/blog/domain-verification-bypass-prevention-caa-accounturi/

Installation
=============

* Install dependencies:

::

   apt install python3-cryptography

Internal check
----------------

* Identify where your local certs are stored. If you are using dehydrated, look into your config file, for example
  ``/etc/dehydrated/config``. There check the setting ``CERTDIR`` and ``BASEDIR``. If there is nothing specific,
  certificates may be stored locally in ``/etc/dehydrated/certs``.
  
* The check script will be run under a separate user ID. The user ``nobody`` does not work here,
  because we need to store runtime files and these should not be written by other users. Hence, we are creating a new user:

::

    INSTALLDIR=/var/lib/check-transparency-logs
    adduser --shell /bin/false --home $INSTALLDIR --system --group check-transparency-logs

* Install program code:

::

    cd $INSTALLDIR
    git clone https://www.github.com/nitram2342/check-transparency-logs.git src

* Prepare a writeable directory for storage files:

::

    mkdir $INSTALLDIR/db

* Obtain the certificates you trust and you use as trust anchors. Here, we use intermediate CA certificates, because we
  verify if a found certificate was signed by one of the trust anchors. If there is an intermediate certificate missing,
  the signature verification will fail. The ``letsencryptauthorityx3.pem`` is expired, but you may still have some
  certs, which have been signed by this certificate.

::

    mkdir $INSTALLDIR/trusted-certs
    cd $INSTALLDIR/trusted-certs
    wget https://letsencrypt.org/certs/lets-encrypt-r3.pem
    wget https://letsencrypt.org/certs/letsencryptauthorityx3.pem

* Check hashes:

::
   
    sha256sum *.pem
    e231300b2b023d34f4972a5b9bba2c189a91cbfc7f80ba8629d2918d77ef1480  letsencryptauthorityx3.pem
    177e1b8fc43b722b393f4200ff4d92e32deeffbb76fef5ee68d8f49c88cf9d32  lets-encrypt-r3.pem
    
* An issue, we find in almost any pentest of OS environments are broken permissions. Therefor, run:

::

    chown check-transparency-logs $INSTALLDIR/trusted-certs $INSTALLDIR/db
    chgrp check-transparency-logs $INSTALLDIR/trusted-certs $INSTALLDIR/db
    chmod 750 $INSTALLDIR/trusted-certs $INSTALLDIR/db


* As a last step of the installation, the script must be run. The script can be run in interactive mode or fully automated.
* To run the script in interactive mode, log into a target server and run:

::

    cd $INSTALLDIR/src
    ./check_ct_local.py \
        --verbose \
        --interactive \
        --hostname www.pentagrid.ch \
        --local-certs /var/lib/dehydrated/certs/www.pentagrid.ch \
        --trusted-issuer-certs ../trusted-certs/

* To run the script in automated mode, run the script on the target server, for example with (adjust parameters accordingly):

::

    HOSTNAME=www.pentagrid.ch
    /var/lib/check-transparency-logs/check_ct_local.py \
        --learn \
        --hostname $HOSTNAME \
        --local-certs /var/lib/dehydrated/certs/$HOSTNAME/$HOSTNAME \
        --trusted-issuer-certs /var/lib/check-transparency-logs/trusted-certs/


External check
----------------

* Now, define the check command. Depending on your setup, edit for example
  ``/etc/icinga2/conf.d/commands_check_ct_extern.conf``:

::

    object CheckCommand "ct_extern" {
      import "plugin-check-command"

      command = [ "/usr/local/bin/check_ct_loop.py",
              "--mail-from", "$mail_loop_mail_from$",
              "--mail-to", "$mail_loop_mail_to$",
              "--smtp-host", "$mail_loop_smtp_host$",
              "--smtp-port", "$mail_loop_smtp_port$",
              "--smtp-user", "$mail_loop_smtp_user$",
              "--imap-host", "$mail_loop_imap_host$",
              "--imap-port", "$mail_loop_imap_port$",
              "--imap-user", "$mail_loop_imap_user$",
              "--imap-spam", "$mail_loop_imap_spam$",
              "--imap-cleanup" ]
    }

* Set up dedicated E-mail accounts. The flag ``--imap-cleanup`` instructs the plugin to remove all E-mails from the IMAP account.

* Add a configuration file for Icinga, for example ``/etc/icinga2/conf.d/services_mail_loop.conf``:

::

    object Service "mail-loop-mail.example.org" {
      import "generic-service-internet"
      host_name = "mail.example.org"
      check_command = "mail_loop"

      vars.mail_loop_mail_from = "test-smtp@example.org"
      vars.mail_loop_mail_to = "mytestaccount@gmail.com"

      # Configuration for E-mail delivery.
      vars.mail_loop_smtp_host = "mail.example.org"
      vars.mail_loop_smtp_port = "465"
      vars.mail_loop_smtp_user = "test-smtp@example.org"
      vars.mail_loop_smtp_pass = "secret"

      # IMAP configuration on the Receiving side.
      # If you use Gmail, you need to enable IMAP with password.
      vars.mail_loop_imap_host = "imap.gmail.com"
      vars.mail_loop_imap_port = "993"
      vars.mail_loop_imap_user = "mytestaccount@gmail.com"
      vars.mail_loop_imap_pass = "secret"
      vars.mail_loop_imap_spam = "[Gmail]/Spam"

      # Be polite and do not send too frequently.
      check_interval = 24h
      max_check_attempts = 4
      retry_interval = 4h
    }



* Fix permissions of your config file. Otherwise passwords may leak.

::

 chown root.icinga /etc/icinga2/conf.d/services_mail_loop.conf
 chmod 640 /etc/icinga2/conf.d/services_mail_loop.conf


Copyright and Licence
=====================

``check_mail_loop.py`` is developed by Martin Schobert <martin@pentagrid.ch> and
published under a BSD licence with a non-military clause. Please read
``LICENSE.txt`` for further details.

