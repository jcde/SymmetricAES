namespace ICB.Domain.Security.Crypto
{
	internal static class EntropyHolder
	{
	    static internal byte[] Entropy
		{
			get
			{
				if (EntropyHolder.entropy == null)
				{
					lock (typeof(EntropyHolder))
					{
						if (EntropyHolder.entropy == null)
						{
							EntropyHolder.entropy = EntropyHolder.CreateEntropy();
						}
					}
				}
				return EntropyHolder.entropy;
			}
		}

		static private byte[] CreateEntropy()
		{
			return new byte[]
				{
					10, 10, 25,
					40 + 15,
					1, 2, 3, 4, 5,
					20, 20, 20,
					100 + 9, 5 + 5,
					10 + 17,
					7 + 8, 50,
					20, 20, 20
				};
		}

		static private byte[] entropy;
	}
}