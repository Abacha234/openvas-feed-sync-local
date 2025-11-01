# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884776");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:05 +0000 (Sat, 16 Sep 2023)");
  script_name("Fedora: Security Advisory for php-phpmailer6 (FEDORA-2023-f9877b5292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-f9877b5292");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3ENKQJPHWC536WHKLGMOHB5FXKOTFE53");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-phpmailer6'
  package(s) announced via the FEDORA-2023-f9877b5292 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PHPMailer - A full-featured email creation and transfer class for PHP

Class Features

  * Probably the world&#39, s most popular code for sending email from PHP!

  * Used by many open-source projects:
  WordPress, Drupal, 1CRM, SugarCRM, Yii, Joomla! and many more

  * Integrated SMTP support - send without a local mail server

  * Send emails with multiple To, CC, BCC and Reply-to addresses

  * Multipart/alternative emails for mail clients that do not read HTML email

  * Add attachments, including inline

  * Support for UTF-8 content and 8bit, base64, binary, and quoted-printable
  encodings

  * SMTP authentication with LOGIN, PLAIN, CRAM-MD5 and XOAUTH2 mechanisms
  over SSL and SMTP+STARTTLS transports

  * Validates email addresses automatically

  * Protect against header injection attacks

  * Error messages in 47 languages!

  * DKIM and S/MIME signing support

  * Compatible with PHP 5.5 and later

  * Namespaced to prevent name clashes

  * Much more!


Autoloader: /usr/share/php/PHPMailer/PHPMailer6/autoload.php");

  script_tag(name:"affected", value:"'php-phpmailer6' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
