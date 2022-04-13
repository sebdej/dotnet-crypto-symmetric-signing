//  Copyright 2022 Sébastian Dejonghe
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System.Security.Cryptography;
using System.Text;

void ExportBase64SharedKey(byte[] key, string path)
{
    File.WriteAllText(path, Convert.ToBase64String(key));
}

byte[] ImportBase64SharedKey(string path)
{
    return Convert.FromBase64String(File.ReadAllText(path));
}

string SignData(byte[] data)
{
    var hmac = new HMACSHA384(ImportBase64SharedKey("shared.key"));

    var signature = hmac.ComputeHash(data);

    return Convert.ToBase64String(data) + "." + Convert.ToBase64String(signature);
}

byte[] VerifyAndGetData(string signedData)
{
    int comma = signedData.IndexOf('.');

    if (comma < 0)
    {
        throw new ArgumentException("Invalid signed data");
    }

    var payload = Convert.FromBase64String(signedData.Substring(0, comma));

    var hmac = new HMACSHA384(ImportBase64SharedKey("shared.key"));

    var givenSignature = Convert.FromBase64String(signedData.Substring(comma + 1));
    var expectedSignature = hmac.ComputeHash(payload);

    if (!givenSignature.SequenceEqual(expectedSignature))
    {
        throw new ArgumentException("Tampered data");
    }

    return payload;
}

ExportBase64SharedKey(RandomNumberGenerator.GetBytes(64), "shared.key");

var plainText = Encoding.UTF8.GetBytes("Hello world!");

var signedData = SignData(plainText);

var verifiedData = VerifyAndGetData(signedData);

Console.WriteLine("Verified data: {0}", Encoding.UTF8.GetString(verifiedData));