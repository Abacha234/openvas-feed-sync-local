# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833305");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-42265", "CVE-2024-0074", "CVE-2024-0075");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-12 16:54:32 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-08 02:00:51 +0000 (Fri, 08 Mar 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2024:0770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0770-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YFZHMPNEJOXMXVXXUK4D7WPRRKBSWLEI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2024:0770-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed
  fixes the following issues:

  Update to 550.54.14

  * Added vGPU Host and vGPU Guest support. For vGPU Host, please refer to the
      README.vgpu packaged in the vGPU Host Package for more details.

  Security issues fixed:

  * CVE-2024-0074: A user could trigger a NULL ptr dereference.

  * CVE-2024-0075: A user could overwrite the end of a buffer, leading to
      crashes or code execution.

  * CVE-2022-42265: A unprivileged user could trigger an integer overflow which
      could lead to crashes or code execution.

  * create /run/udev/static_node-tags/uaccess/nvidia${devid} symlinks also
      during modprobing the nvidia module  this changes the issue of not having
      access to /dev/nvidia${devid}, when gfxcard has been replaced by a different
      gfx card after installing the driver

  * provide nvidia-open-driver-G06-kmp (jsc#PED-7117)

  * this makes it easy to replace the package from nVidia's CUDA repository with
      this presigned package

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
