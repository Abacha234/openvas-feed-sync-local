# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891675");
  script_cve_id("CVE-2019-6690");
  script_tag(name:"creation_date", value:"2019-02-13 23:00:00 +0000 (Wed, 13 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-06 18:27:00 +0000 (Wed, 06 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-1675)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1675");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1675");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-gnupg' package(s) announced via the DLA-1675 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Kjall and Stig Palmquist discovered a vulnerability in python-gnupg, a wrapper around GNU Privacy Guard. It was possible to inject data through the passphrase property of the gnupg.GPG.encrypt() and gnupg.GPG.decrypt() functions when symmetric encryption is used. The supplied passphrase is not validated for newlines, and the library passes --passphrase-fd=0 to the gpg executable, which expects the passphrase on the first line of stdin, and the ciphertext to be decrypted or plaintext to be encrypted on subsequent lines.

By supplying a passphrase containing a newline an attacker can control/modify the ciphertext/plaintext being decrypted/encrypted.

For Debian 8 Jessie, this problem has been fixed in version 0.3.6-1+deb8u1.

We recommend that you upgrade your python-gnupg packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python-gnupg' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);