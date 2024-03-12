from django.core.mail import EmailMessage
from django.core.mail.backends.smtp import EmailBackend
from master.settings import EMAIL_HOST, EMAIL_PORT, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD, EMAIL_USE_TLS
from django.core.mail import send_mail
from rest_framework import status

""" Send email function """
def send_email(subject, message, mail_to, mail_from=None, attachement=None):
    try:
        backend = EmailBackend(host=EMAIL_HOST, port=EMAIL_PORT, username=EMAIL_HOST_USER, 
                            password=EMAIL_HOST_PASSWORD, use_tls=EMAIL_USE_TLS)
        
        if mail_from is None: mail_from = EMAIL_HOST_USER
        sent = EmailMessage(subject, message, mail_from, [mail_to], connection=backend)
        print(mail_to, mail_from)
        if attachement: sent.attach_file(attachement)
        try : 
            print("demo")
            status = sent.send()
            return status
        except Exception as err:
            raise ValueError(err)
    except Exception as err:
        raise ValueError(err)