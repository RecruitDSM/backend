#! /usr/bin/python

import os
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

DEST_EMAIL_ADDR = os.environ.get('DEST_EMAIL_ADDR')
SERVICE_ADDR = os.environ.get('SERVICE_ADDR')

def send_mail(student, company_name, document_file_path):
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'{student} 채용지원서 제출'
        msg['From'] = SERVICE_ADDR
        msg['To'] = DEST_EMAIL_ADDR

        html = f'<p>{student} {company_name} 채용 지원합니다.</p><a target="_black" href={document_file_path}>{document_file_path}</a>'

        content = MIMEText(html, 'html')

        msg.attach(content)

        s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        s.login(SERVICE_ADDR, 'ddzetdzjbbgtyezx')

        s.sendmail(SERVICE_ADDR, DEST_EMAIL_ADDR, msg.as_string())
        s.quit()
