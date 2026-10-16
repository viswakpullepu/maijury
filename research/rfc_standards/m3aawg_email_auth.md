Email Authentication | Messaging, Malware and Mobile Anti-Abuse Working Group  [Skip to main content](#main-content) 

[![Home](/themes/custom/aero10/logo.svg)](/)

* About Us  Toggle submenu

  ![About Us](/sites/default/files/inline-images/mm-about-us.jpg)

  The Messaging, Malware, and Mobile Anti-Abuse Working Group provides a collaborative global trusted forum that brings industry together to help fight and prevent online abuse.

  + Who We Are

    - [Why M3AAWG](/about-m3aawg)
    - [Our Members](/about/roster)
    - [Our Partners](/our-partners)
    - [Leadership](/leadership)
    - [Expert Advisors](/members/M3AAWG-expert-advisors)
    - [M3AAWG Strategies](/M3AAWGStrategies)

  + Get Involved

    - [Join Us - Membership](/join)
    - [M3AAWG Awards](/awards)
    - [Contact Us](/contact-us)
  + Resources

    - [About Us Resources](/AboutUsResources)
    - [Consumer Information](/consumer-information)
* Meetings  Toggle submenu

  ![Meetings ](/sites/default/files/inline-images/mm-meetings.jpg)

  M3AAWG meetings are an exceptional opportunity to discuss the latest in anti-abuse with other professionals in a focused environment of working sessions and educational panels.

  + Upcoming Events

    - [Upcoming Meetings](/upcoming-meetings)
    - [Call for Proposals](/events/call-for-proposals)
  + Meeting Resources

    - [M3AAWG Glossary](/glossary)
    - [Training Videos](/activities/maawg-training-series-videos)
    - [Keynotes Videos](/keynote-videos)

  ![68th General Meeting](/sites/default/files/styles/large/public/general_meeting/Paris-Web-Image_small.jpg.webp?itok=UJZF5-kk)

  #### 68th General Meeting

  October 26–29, 2026

  Paris, France

  Paris Marriott Rive Gauche Hotel

  ![](/sites/default/files/country-flags/svg/fr.svg) Learn more

  [meeting link](/events/68th-general-meeting)
* [For the Industry](/for-the-industry)  Toggle submenu

  ![For The Industry](/sites/default/files/inline-images/default-image-01.jpg)

  M3AAWG develops comprehensive best practices, technical summaries, and policy guidance to help organizations combat messaging abuse, malware, and mobile threats with proven industry standards.

  + Best Practices

    - [Best Practices](/published-documents)
    - [Multiple Languages](/multiple-languages)
    - [Supporting Documents](/supporting-documents)
  + Policy & Advocacy

    - [Public Policy Comments](/for-the-industry/published-comments)

  + Technical Resources

    - [Technology Summaries](/TechnologySummaries)
    - [Feedback Loop Resources](/fbl-resources)
    - [ABCs for ISPs](/abcs-for-ISP-code)
    - [Outreach](/outreach)
* News  Toggle submenu

  ![](/sites/default/files/inline-images/mm-menu-news-01-1_0.jpg)

  Stay connected with M3AAWG through our blog, press releases, social media channels, and industry coverage highlighting collaborative efforts and innovations in the fight against online abuse.

  + News

    - [Social Media](/social-media)
    - [M3AAWG Blog](/blog)
    - [M3AAWG 5 Episodes](/m3aawg-5-episodes)
    - [News Releases](/m3aawg-news-releases)
    - [M3AAWG in the News](/m3aawg-news)

  M3AAWG Blog - Recent Posts
  --------------------------

  [M3AAWG68 Heads to Paris during Cybersecurity Awareness Month](/blog/M3AAWG68HeadsToParis)

  [The 2027 SMTP Client Authentication Trust Gap: Email Needs a New Industry Model](/blog/2027SMTPClientAuthTrustGap)

  [Helping the CRTC Modernize Canada's Rules on Unwanted Calls](/blog/CRTCModernizCanadasRulesOnUnwantedCalls)

  [View all posts](/blog)
* [Members](https://www.m3aawg.org/members/members-home)  Toggle submenu

  + Access & Login

    - [Login](/login)
    - [Request Member ID & Login](/join/request)
    - [Forgot Password](/reset-pass)
* Search

   

Email Authentication
====================

1. [Home](/)
2. [Technology Summaries](/TechnologySummaries)
3. Email Authentication

![](/sites/default/files/cover-image/default/cover-image-1.jpg)

### 

###### [Download the M3AAWG Technology Summaries: Email Authentication (English)](/system/files/legacy/emailauth_techsummary.pdf)

###### [(Japanese)](/system/files/legacy/email_auth_tech_summary_en_jp.pdf)

### What email authentication is:

Email authentication involves one or more technical processes used by sending and receiving mail systems to verify the email originated with an authorized domain name server and is received in a valid format. Email authentication creates signals about the mail that can be used in spam filtering and other mail handling decisions, and may even point to fraudulent senders.

Two widely used email authentication protocols are Sender Policy Framework (SPF) and Domain Keys Identified Mail (DKIM). Both SPF and DKIM provide information used by the receiving domain to verify the sender of the message was authorized by the sending domain. DKIM can also determine if the content received is the same as it was when sent.

Domain-based Message, Reporting, and Conformance (DMARC) is a protocol that is layered on top of SPF and DKIM. DMARC helps receiving domains decide how best to handle messages that fail authentication.

### What email authentication does:

* Email authentication associates an identity (usually a domain name) with an email message by verifying key information that indicates the identity handled the message in some way.
* The identity informs how the message is processed. For instance, if the domain has a poor reputation (frequently associated with spam), the system may classify the message as spam.
* A single message might be associated with multiple identities, each separately authenticated, that are used to inform the processing of the message.

### What email authentication does not do:

* Email authentication does not attest to the authenticity or quality of the message’s content or ensure that the message is “good” or “legitimate.”
* Email authentication makes no statement about what entity actually wrote the message.
* Email could fail authentication for legitimate reasons such as mail server configuration or syntax errors. Failed authentication by SPF or DKIM is equivalent to–and is no worse than–the absence of authentication, absent other indications (such as DMARC).

### 

### [References:](/TechnologySummaries/EmailAuthentication)

RFC 6376, “[DomainKeys Identified Mail (DKIM) Signatures](https://www.rfc-editor.org/rfc/rfc6376.html)”

RFC 7208, “[Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1](https://www.rfc-editor.org/rfc/rfc7208.html)”

RFC 7489, “[Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489.html)”

“[M3AAWG Email Authentication Recommended Best Practices](/sites/default/files/legacy/m3aawg-email-authentication-recommended-best-practices-09-2020.pdf)”

Attached Documents

[emailauth\_techsummary.pdf](/system/files/2026-01/emailauth_techsummary.pdf) (40.56 KB)

[email\_auth\_tech\_summary\_en\_jp.pdf](/system/files/2026-01/email_auth_tech_summary_en_jp.pdf) (161.88 KB)

[![m3aawg logo](/sites/default/files/m3aawg-favicon.png)](/)

Footer menu
-----------

* [Contact Us](/contact-us)
* [Media](/media-contact)
* [Conduct Policy](/conduct-policy)
* [Privacy Notice](/privacy-notice)

**© Copyright 2026**  - Messaging, Malware and Mobile Anti-Abuse Working Group ( **M3AAWG** )

P.O. Box 9125, Brea, CA 92822

* [Facebook](https://www.facebook.com/M3AAWG)
* [Linkedin](https://www.linkedin.com/company/m3aawg/)
* [Youtube](https://www.youtube.com/user/MAAWG)