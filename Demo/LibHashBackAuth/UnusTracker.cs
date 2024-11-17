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

        /// <summary>
        /// Tests if the supplied Unus string (in byte form) has
        /// already been used. If not, adds hash of bytes to list.
        /// </summary>
        /// <param name="unus">Supplied Unus string in byte form.</param>
        /// <returns>
        /// True if Unus has already been used.
        /// False if this is the first time.
        /// </returns>
        internal bool IsReused(long hash)
        {
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
    }
}
