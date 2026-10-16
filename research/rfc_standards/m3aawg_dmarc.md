M3AAWG Technology Summary: DMARC (Domain-based Message Authentication, Reporting, and Conformance) | Messaging, Malware and Mobile Anti-Abuse Working Group  [Skip to main content](#main-content) 

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

   

M3AAWG Technology Summary: DMARC (Domain-based Message Authentication, Reporting, and Conformance)
==================================================================================================

1. [Home](/)
2. [Technology Summaries](/TechnologySummaries)
3. M3AAWG Technology Summary: DMARC (Domain-based Message Authentication, Reporting, and Conformance)

![](/sites/default/files/cover-image/default/cover-image-4.jpg)

What DMARC is:
--------------

DMARC is a mechanism that uses the email authentication protocols DKIM and SPF to ensure that the use of a domain in the “From” line of an email message, or the sender address, is authorized by the domain owner. A domain owner announces that a domain’s authorized usage can be validated by publishing a specially formatted TXT record in the DNS.

What DMARC does:
----------------

* DMARC is designed to prevent unauthorized use (spoofing) of the domain in the “From” line of an email message. When domains participate in DMARC, any site that receives an email message, or the receiving site, can apply the DMARC mechanism to validate whether the domain owner authorized its usage.
* DMARC lets domain owners request that email messages that do not pass DMARC validation checks be routed to the spam folder (quarantined) or rejected entirely. A receiving site can use this handling request to inform its decision for disposition of such messages.
* DMARC also provides a method for domain owners to receive emailed reports from receiving organizations. These reports contain aggregate data about DMARC validation results for those messages that use the domain in the sender address.

What DMARC does not do:
-----------------------

* DMARC does not attest to the legitimacy or quality of the message content or sender. A DMARC pass only means that the use of the domain in the message’s “From” line was authorized by the domain owner.
* Because it relies on DKIM and SPF, DMARC is subject to the same fragility as these protocols as it relates to message alteration and indirect message flows, such as forwarding and mailing lists.
* DMARC does not prevent abuse using “lookalike” or “close cousin” domains. For example, a bank might protect its “bigbank.com” domain with DMARC, but this by itself will not prevent bad actors from using “b1gbank.com” or similar spoofing tactics.
* DMARC does not prevent “display name” attacks, where the attacker sends email using an arbitrary domain and a well-known or trusted name in the display name, such as in this example:

From: “Big Bank” [badguy@example.com](mailto:badguy@spammer.com)>

References:
-----------

* [Domain-based Message Authentication, Reporting, and Conformance (RFC 7489)](https://datatracker.ietf.org/doc/html/rfc7489)
* [Proposed updates to RFC 7489 (DMARCbis)](https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/)
* [Sender Policy Framework (RFC 7208)](https://datatracker.ietf.org/doc/html/rfc7208)
* [DomainKeys Identified Mail Signatures (RFC 6376)](https://datatracker.ietf.org/doc/html/rfc6376)
* [M3AAWG Email Authentication Recommended Best Practices](/sites/default/files/legacy/m3aawg-email-authentication-recommended-best-practices-09-2020.pdf)
* [M3AAWG Protecting Parked Domains Best Common Practices](/M3AAWG-Protecting-Parked-Domains-BCP-update-2022-06)
* [M3AAWG Technology Summaries - SPF](/TechnologySummaries/SenderPolicyFramework)
* [M3AAWG Technology Summaries - DKIM](/TechnologySummaries/DKIM)

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