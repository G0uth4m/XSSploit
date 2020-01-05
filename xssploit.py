import argparse
import re
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse

def get_arguments():
	parser = argparse.ArgumentParser()

	parser.add_argument("-u", "--url", dest="url", help="URL")
	parser.add_argument("-x", "--xss-payloads", dest="payloads", help="XSS payloads wordlist")
	parser.add_argument("-p", "--parameter", dest="parameter", help="Parameter to test")

	options = parser.parse_args()

	if not options.url or not options.payloads or not options.payloads:
		parser.print_help()
		exit()

	return options

def test_reflection(parameter, url, value_of_parameter):
	test_input = "hello123"
	url = url.strip('#')
	new_url = url.replace(parameter + "=" + value_of_parameter, parameter + "=" + test_input)
	response = requests.get(new_url)

	if test_input in response.text:
		return True
	return False

def test_alert(browser, url):
	browser.get(url)
	try:
		WebDriverWait(browser, 3).until(EC.alert_is_present(), "")
		alert = browser.switch_to.alert
		alert.accept()
		return True
	except TimeoutException:
		return False

def main():
	options = get_arguments()
	url = options.url + "#"
	payloads = options.payloads
	parameter = options.parameter

	value_of_parameter = re.findall("(?:" + parameter + "=)(.*?)[&|#]", url)

	if not test_reflection(parameter, url, value_of_parameter[0]):
		print("[-] User input does not reflect in response.\n[-] URL may not be vulnerable to XSS")
		choice = input("[*] Do you still want to continue brute forcing XSS payloads?[Y/n] ")
		if choice in ["n", "no", "N", "No", "NO"]:
			exit()
	else:
		print("[+] Input reflection detected\n[*] Brute forcing XSS payloads now ...")

	url = url.strip('#')

	crafted_urls = []

	with open(payloads, 'r', encoding='utf-8') as f:
		for line in f:
			payload = line.strip()
			new_url = url.replace(parameter + "=" + value_of_parameter[0], parameter + "=" + payload)
			crafted_urls.append(new_url)

	xss_vuln = []

	browser = webdriver.Firefox(executable_path="geckodriver.exe")

	for i in crafted_urls:
		print("[*] Testing : " + i)
		if test_alert(browser, i):
			print("[+] Alert detected in : " + i)
			xss_vuln.append(i)

	print("\nAlert detected in the following URLs : \n")
	for i in xss_vuln:
		print("[+] " + i)

if __name__ == "__main__":
	main()