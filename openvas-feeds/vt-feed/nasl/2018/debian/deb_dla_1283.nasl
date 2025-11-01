# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891283");
  script_tag(name:"creation_date", value:"2018-02-20 23:00:00 +0000 (Tue, 20 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-1283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1283");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1283-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-crypto' package(s) announced via the DLA-1283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is an update to DLA-1283-1. In DLA-1283-1 it is claimed that the issue described in CVE-2018-6594 is fixed. It turns out that the fix is partial and upstream has decided not to fix the issue as it would break compatibility and that ElGamal encryption was not intended to work on its own.

The recommendation is still to upgrade python-crypto packages. In addition please take into account that the fix is not complete. If you have an application using python-crypto is implementing ElGamal encryption you should consider changing to some other encryption method.

There will be no further update to python-crypto for this specific CVE. A fix would break compatibility, the problem has been ignored by regular Debian Security team due to its minor nature and in addition to that we are close to the end of life of the Wheezy security support.

CVE-2018-6594

python-crypto generated weak ElGamal key parameters, which allowed attackers to obtain sensitive information by reading ciphertext data (i.e., it did not have semantic security in face of a ciphertext-only attack).

We recommend that you upgrade your python-crypto packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]

For Debian 7 Wheezy, these issues have been fixed in python-crypto version 2.6-4+deb7u8");

  script_tag(name:"affected", value:"'python-crypto' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);