namespace ICB.Domain.Security
{
	/// <summary>
	/// Presents information about certain license
	/// </summary>
	public sealed class LicenseInfo
	{
	    public string InstallId { get; set; }

        public string ProductName { get; set; }

		public LicenseStatus LicenseStatus { get; set; }
	}
}
