# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856097");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-28737", "CVE-2023-40546", "CVE-2023-40547", "CVE-2023-40548", "CVE-2023-40549", "CVE-2023-40550", "CVE-2023-40551");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 19:25:40 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-04-23 01:06:09 +0000 (Tue, 23 Apr 2024)");
  script_name("openSUSE: Security Advisory for shim (SUSE-SU-2024:1368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1368-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AUKLAMRNZRUUXNO3MFBSDVZSOVFMZOPX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim'
  package(s) announced via the SUSE-SU-2024:1368-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shim fixes the following issues:

  * Update shim-install to set the TPM2 SRK algorithm (bsc#1213945)

  * Limit the requirement of fde-tpm-helper-macros to the distro with
      suse_version 1600 and above (bsc#1219460)

  Update to version 15.8:

  Security issues fixed:

  * mok: fix LogError() invocation (bsc#1215099,CVE-2023-40546)

  * avoid incorrectly trusting HTTP headers (bsc#1215098,CVE-2023-40547)

  * Fix integer overflow on SBAT section size on 32-bit system
      (bsc#1215100,CVE-2023-40548)

  * Authenticode: verify that the signature header is in bounds
      (bsc#1215101,CVE-2023-40549)

  * pe: Fix an out-of-bound read in verify_buffer_sbat()
      (bsc#1215102,CVE-2023-40550)

  * pe-relocate: Fix bounds check for MZ binaries (bsc#1215103,CVE-2023-40551)

  The NX flag is disable which is same as the default value of shim-15.8, hence,
  not need to enable it by this patch now.

  * Generate dbx during build so we don't include binary files in sources

  * Don't require grub so shim can still be used with systemd-boot

  * Update shim-install to fix boot failure of ext4 root file system on RAID10
      (bsc#1205855)

  * Adopt the macros from fde-tpm-helper-macros to update the signature in the
      sealed key after a bootloader upgrade

  * Update shim-install to amend full disk encryption support

  * Adopt TPM 2.0 Key File for grub2 TPM 2.0 protector

  * Use the long name to specify the grub2 key protector

  * cryptodisk: support TPM authorized policies

  * Do not use tpm_record_pcrs unless the command is in command.lst

  * Removed POST_PROCESS_PE_FLAGS=-N from the build command in shim.spec to
      enable the NX compatibility flag when using post-process-pe after discussed
      with grub2 experts in mail. It's useful for further development and testing.
      (bsc#1205588)

  ##");

  script_tag(name:"affected", value:"'shim' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
