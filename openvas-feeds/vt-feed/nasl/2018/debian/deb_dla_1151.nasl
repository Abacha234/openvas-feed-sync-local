# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891151");
  script_cve_id("CVE-2016-9263", "CVE-2017-14718", "CVE-2017-14719", "CVE-2017-14720", "CVE-2017-14721", "CVE-2017-14722", "CVE-2017-14723", "CVE-2017-14725");
  script_tag(name:"creation_date", value:"2018-02-06 23:00:00 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-10 02:29:00 +0000 (Fri, 10 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-1151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1151");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1151-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DLA-1151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The fix for CVE-2017-14990 issued as DLA-1151-1 was incomplete and caused a regression. It was discovered that an additional database upgrade and further code changes would be necessary. At the moment these changes are deemed as too intrusive and thus the initial patch for CVE-2017-14990 has been removed again. For reference, the original advisory text follows.

WordPress stores cleartext wp_signups.activation_key values (but stores the analogous wp_users.user_activation_key values as hashes), which might make it easier for remote attackers to hijack unactivated user accounts by leveraging database read access (such as access gained through an unspecified SQL injection vulnerability).

For Debian 7 Wheezy, these problems have been fixed in version 3.6.1+dfsg-1~deb7u19.

We recommend that you upgrade your wordpress packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);