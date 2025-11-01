# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856735");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-10458", "CVE-2024-10459", "CVE-2024-10460", "CVE-2024-10461", "CVE-2024-10462", "CVE-2024-10463", "CVE-2024-10464", "CVE-2024-10465", "CVE-2024-10466", "CVE-2024-10467", "CVE-2024-11159");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-04 13:26:32 +0000 (Mon, 04 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-26 05:00:20 +0000 (Tue, 26 Nov 2024)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (SUSE-SU-2024:4050-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4050-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HD7VY4CJZNLYWT74XDD2HN4OERQPRMJ4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the SUSE-SU-2024:4050-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  * Mozilla Thunderbird 128.4.3

  * fixed: Folder corruption could cause Thunderbird to freeze and become
      unusable

  * fixed: Message corruption could be propagated when reading mbox

  * fixed: Folder compaction was not abandoned on shutdown

  * fixed: Folder compaction did not clean up on failure

  * fixed: Collapsed NNTP thread incorrectly indicated there were unread
      messages

  * fixed: Navigating to next unread message did not wait for all messages to be
      loaded

  * fixed: Applying column view to folder and children could break if folder
      error occurred

  * fixed: Remote content notifications were broken with encrypted messages

  * fixed: Updating criteria of a saved search resulted in poor search
      performance

  * fixed: Drop-downs may not work in some places

  * fixed: Security fixes MFSA 2024-61 (bsc#1233355)

  * CVE-2024-11159 Potential disclosure of plaintext in OpenPGP encrypted
      message

  * Mozilla Thunderbird 128.4.2

  * changed: Increased the auto-compaction threshold to reduce frequency of
      compaction

  * fixed: New profile creation caused console errors

  * fixed: Repair folder could result in older messages showing wrong date and
      time

  * fixed: Recently deleted messages could become undeleted if message
      compaction failed

  * fixed: Visual and UX improvements

  * fixed: Clicking on an HTML button could cause Thunderbird to freeze

  * fixed: Messages could not be selected for dragging

  * fixed: Could not open attached file in a MIME encrypted message

  * fixed: Account creation 'Setup Documentation' link was broken

  * fixed: Unable to generate QR codes when exporting to mobile in some cases

  * fixed: Operating system reauthentication was missing when exporting QR codes
      for mobile

  * fixed: Could not drag all-day events from one day to another in week view

  * Mozilla Thunderbird 128.4.1

  * new: Add the 20 year donation appeal

  * Mozilla Thunderbird 128.4

  * new: Export Thunderbird account settings to Thunderbird Mobile via QRCode

  * fixed: Unable to send an unencrypted response to an OpenPGP encrypted
      message

  * fixed: Thunderbird update did not update language pack version until another
      restart

  * fixed: Security fixes MFSA 2024-58 (bsc#1231879)

  * CVE-2024-10458 Permission leak via embed or object elements

  * CVE-2024-10459 Use-after-free in layout with accessibility

  * CVE-2024-10460 Confusing display of origin for ext ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
