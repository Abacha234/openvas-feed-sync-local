# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893239");
  script_cve_id("CVE-2022-24765", "CVE-2022-29187", "CVE-2022-39253", "CVE-2022-39260");
  script_tag(name:"creation_date", value:"2022-12-14 02:00:16 +0000 (Wed, 14 Dec 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-21 18:26:00 +0000 (Fri, 21 Oct 2022)");

  script_name("Debian: Security Advisory (DLA-3239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3239");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3239-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/git");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git' package(s) announced via the DLA-3239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In rare conditions, the previous git update released as DLA-3239-1 could generate a segmentation fault, which prevented its availability on armhf architecture. This update addresses this issue. For reference the original advisory text follows.

Multiple issues were found in Git, a distributed revision control system. An attacker may cause other local users into executing arbitrary commands, leak information from the local filesystem, and bypass restricted shell. Note: Due to new security checks, access to repositories owned and accessed by different local users may now be rejected by Git, in case changing ownership is not practical, git displays a way to bypass these checks using the new safe.directory configuration entry. CVE-2022-24765 Git is not checking the ownership of directories in a local multi-user system when running commands specified in the local repository configuration. This allows the owner of the repository to cause arbitrary commands to be executed by other users who access the repository. CVE-2022-29187 An unsuspecting user could still be affected by the issue reported in CVE-2022-24765, for example when navigating as root into a shared tmp directory that is owned by them, but where an attacker could create a git repository. CVE-2022-39253 Exposure of sensitive information to a malicious actor. When performing a local clone (where the source and target of the clone are on the same volume), Git copies the contents of the source's `$GIT_DIR/objects` directory into the destination by either creating hardlinks to the source contents, or copying them (if hardlinks are disabled via `--no-hardlinks`). A malicious actor could convince a victim to clone a repository with a symbolic link pointing at sensitive information on the victim's machine. CVE-2022-39260 `git shell` improperly uses an `int` to represent the number of entries in the array, allowing a malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code execution on a victim machine. For Debian 10 buster, this problem has been fixed in version 1:2.20.1-2+deb10u6. We recommend that you upgrade your git packages. For the detailed security status of git please refer to its security tracker page at: [link moved to references] Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'git' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);