import smtplib

class Mailer:
    def __init__(self, config):
        try:
            self.sendfrom = config["sender"]
            self.sendto = config["receiver"]
            self.server = smtplib.SMTP(config["server"],config["serverport"])
            self.server.connect(config["server"],config["serverport"])
            # print(self.server.ehlo())
            self.server.starttls()
            # print(self.server.ehlo())
            # Enter Your Password instead of None below. Example: "password"
        except:
            print("Error! Mailer misconfigured!")

    def send(self, body=""):
        try:
            self.server.sendmail(self.sendfrom, self.sendto, body)
            self.server.quit()
        except:
            print("Warning! Mail not Send!")
