using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LibHashBackAuth
{
    internal class UnusTracker
    {
        /// <summary>
        /// Collection of hashes that have already been used.
        /// Lock before use.
        /// </summary>
        private readonly Queue<long> usedHashes = new Queue<long>();

        /// <summary>
        /// Number of hashes to store before we clear out old ones.
        /// </summary>
        private const int maxUsedHashCount = 999;

        internal bool IsReused(byte[] unus)
        {
            /* Calculate the hash from these bytes. */
            long hash = HashUnus(unus);

            /* Lock the collection for thread safety. */
            lock (usedHashes)
            {
                /* If the hash is already in the collection,
                 * return indicating it has already been used. */
                if (usedHashes.Contains(hash))
                    return true;

                /* Not present, so add it to the 
                 * collection as the newest. */
                usedHashes.Enqueue(hash);

                /* If there's too many, clear out the eldest
                 * until we're under the limit again. */
                while (usedHashes.Count > maxUsedHashCount)
                    usedHashes.Dequeue();

                /* Return indicating the hash is new. */
                return false;
            }
        }

        private long HashUnus(byte[] unus)
        {
            /* Loop through each byte index in unus, XORing that byte into its
             * place in the hash. Jumping the shifting place by 3 means the 
             * last byte XORs with bits 48-55. */
            long hash = 0;
            for (int unusIndex = 0; unusIndex < unus.Length; unusIndex++)
                hash ^= ((long)unus[unusIndex]) << (unusIndex * 3);

            /* Completed hash. Add a fixed number so the decimal form is the same
             * length. (16 zeros just exceeds the maximum from the above loop.) */
            return hash + 10000000000000000L;
        }
    }
}
