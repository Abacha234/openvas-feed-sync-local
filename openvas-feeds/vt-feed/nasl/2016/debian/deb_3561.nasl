# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703561");
  script_cve_id("CVE-2016-2167", "CVE-2016-2168");
  script_tag(name:"creation_date", value:"2016-04-28 22:00:00 +0000 (Thu, 28 Apr 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-3561)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3561");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3561");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DSA-3561 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Subversion, a version control system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-2167

Daniel Shahaf and James McCoy discovered that an implementation error in the authentication against the Cyrus SASL library would permit a remote user to specify a realm string which is a prefix of the expected realm string and potentially allowing a user to authenticate using the wrong realm.

CVE-2016-2168

Ivan Zhakov of VisualSVN discovered a remotely triggerable denial of service vulnerability in the mod_authz_svn module during COPY or MOVE authorization check. An authenticated remote attacker could take advantage of this flaw to cause a denial of service (Subversion server crash) via COPY or MOVE requests with specially crafted header.

For the stable distribution (jessie), these problems have been fixed in version 1.8.10-6+deb8u4.

For the unstable distribution (sid), these problems have been fixed in version 1.9.4-1.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);