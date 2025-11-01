# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702790");
  script_cve_id("CVE-2013-1739");
  script_tag(name:"creation_date", value:"2013-11-01 23:00:00 +0000 (Fri, 01 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2790)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2790");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2790");
  script_xref(name:"URL", value:"https://developer.mozilla.org/en-US/docs/NSS/NSS_3.14.4_release_notes");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DSA-2790 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the Mozilla Network Security Service library (nss) read uninitialized data when there was a decryption failure. A remote attacker could use this flaw to cause a denial of service (application crash) for applications linked with the nss library.

The oldstable distribution (squeeze) is not affected by this problem.

For the stable distribution (wheezy), this problem has been fixed in version 2:3.14.4-1.

The packages in the stable distribution were updated to the latest patch release 3.14.4 of the library to also include a regression bugfix for a flaw that affects the libpkix certificate verification cache. More information can be found via:

[link moved to references]

For the testing distribution (jessie), this problem has been fixed in version 2:3.15.2-1.

For the unstable distribution (sid), this problem has been fixed in version 2:3.15.2-1.

We recommend that you upgrade your nss packages.");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);