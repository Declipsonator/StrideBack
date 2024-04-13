#  LICENSE: GNU General Public License v3.0
#  Copyright (c) 2024 Declipsonator
#
#  This software can be freely copied, modified, and distributed under the GPLv3
#  license, but requires inclusion of license and copyright notices, and users bear the
#  risk of open-sourcing the codebase if used for business purposes, while
#  modifications must be indicated and distributed under the same license, with no
#  warranties provided and no liability for damages on the part of the author or license.

import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import html as htmll

port = 465  # For SSL


async def send_email(email: str, subject: str, message: str):
    """
    Sends an email to the specified email address with the specified subject and message.

    Args:
        email (str): The email address to send the email to.
        subject (str): The subject of the email.
        message (str): The message of the email.

    Returns:
        bool: True if the email was sent successfully, False otherwise.
    """
    if os.environ['DEVELOPMENT'].lower() == 'true':
        print("""
        Email sent to: {}
        Subject: {}
        Message: {}
        """.format(email, subject, message))
        return True

    # Code to send email
    try:
        password = os.environ['EMAIL_PASSWORD']
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, context=context) as server:
            server.login(os.environ['EMAIL'], password)
            server.sendmail(os.environ['EMAIL'], htmll.escape(email),
                            f"Subject: {htmll.escape(subject)}\n\n{htmll.escape(message)}")
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


async def send_fancy_email(email: str, subject: str, header: str, message: str, footer: str):
    """
    Sends a fancy email to the specified email address with the specified subject, header, message, and footer.

    Args:
        email (str): The email address to send the email to.
        subject (str): The subject of the email.
        header (str): The header of the email.
        message (str): The message of the email.
        footer (str): The footer of the email.

    Returns:
        bool: True if the email was sent successfully, False otherwise.
    """
    if os.environ['DEVELOPMENT'].lower() == 'true':
        print("""
        Email sent to: {}
        Subject: {}
        Header: {}
        Message: {}
        Footer: {}
        """.format(email, subject, header, message, footer))
        return True

    email_message = MIMEMultipart("alternative")
    email_message["Subject"] = htmll.escape(subject)
    email_message["From"] = htmll.escape(os.environ['EMAIL'])
    email_message["To"] = htmll.escape(email)

    text = f"""\
    {htmll.escape(subject)}
    {htmll.escape(header)}
    {htmll.escape(message)}
    {htmll.escape(footer)}
    """
    html = f"""\
    <html>
      <head>
      <style>
        body \u007b
         font-family: "Lucida Console";
         background-color: #E0E0E0;
        \u007d
      
        #main \u007b
            max-width: 500px;
            margin:0 auto;
            border-radius: 30px;
            border: solid;
            border-color: gray;
            border-width: 1px;
            background-color: #F8F8F8;
            padding: 20px;
        \u007d
        
      </style>
      </head>
      <body>
        <div id="main" style="text-align: center;">
            <h2><i><u>EmpireStrides<u><i></h2>
            <h1>{htmll.escape(header)}</h1>
            <hr>
            <h4>{htmll.escape(message)}</h4>
            <p>{htmll.escape(footer)}</p>
        </div>
      </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    email_message.attach(part1)
    email_message.attach(part2)

    try:
        password = os.environ['EMAIL_PASSWORD']
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, context=context) as server:
            server.login(os.environ['EMAIL'], password)
            server.sendmail(os.environ['EMAIL'], email, email_message.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
