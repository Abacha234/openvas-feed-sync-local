# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703466");
  script_cve_id("CVE-2015-8629", "CVE-2015-8631");
  script_tag(name:"creation_date", value:"2016-02-03 23:00:00 +0000 (Wed, 03 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-02 19:15:00 +0000 (Tue, 02 Feb 2021)");

  script_name("Debian: Security Advisory (DSA-3466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3466");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3466");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-3466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in krb5, the MIT implementation of Kerberos. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-8629

It was discovered that an authenticated attacker can cause kadmind to read beyond the end of allocated memory by sending a string without a terminating zero byte. Information leakage may be possible for an attacker with permission to modify the database.

CVE-2015-8630

It was discovered that an authenticated attacker with permission to modify a principal entry can cause kadmind to dereference a null pointer by supplying a null policy value but including KADM5_POLICY in the mask.

CVE-2015-8631

It was discovered that an authenticated attacker can cause kadmind to leak memory by supplying a null principal name in a request which uses one. Repeating these requests will eventually cause kadmind to exhaust all available memory.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.10.1+dfsg-5+deb7u7. The oldstable distribution (wheezy) is not affected by CVE-2015-8630.

For the stable distribution (jessie), these problems have been fixed in version 1.12.1+dfsg-19+deb8u2.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);