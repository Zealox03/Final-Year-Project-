# Final-Year-Project-
An optimized Web Application Firewall (WAF) solution leveraging machine learning to enhance Distributed Denial of Service (DDoS) detection and mitigation in high-availability systems.

## Description
This research aims to analyze the limitations of conventional Web Application Firewalls (WAFs) and explore modern solutions to enhance the current state of WAFs so that they can differentiate legitimate high traffic and malicious traffic accurately. The goal is to explore optimizations to better mitigate application-layer Distributed Denial of Service (DDoS) attacks in a web application environment.

## Theoretical Framework
![image alt](https://github.com/Zealox03/Final-Year-Project-/blob/main/framework.jpeg?raw=true)

## Result
![image alt](https://github.com/Zealox03/Final-Year-Project-/blob/main/result.jpeg?raw=true)

## Key Features 
* Developed with Python programming language.
* Machine learning pipeline was developed with Jupyter Notebook. Evaluations are made on Logistic Regression, Heuristic Model (Conventional WAF), and Random Forest.
* Dataset is self-collected from generating benign and malicious traffic. Structure of data is based on OWASP framework (ModSecurity segment parts).
* Simulation was done on Oracle VM VirtualBox with Ubuntu as the target and Kali Linux as the attacker.
* Machine Learning pipeline is integrated into ModSecurity WAF in Apache server.

## Strengths
* Detects HTTP Flood and GoldenEye.
* Real-time detection
* Blocks malicious reuqests.

## Limitations
* Dataset and codes were hardcoded. Results may be slightly biased.
* Experiment was conducted in a controlled environment and may not be suitable for production.


## Video Demo
https://youtu.be/sa1nOVFFRLQ?si=EZbtYTZRjxsF7beK
