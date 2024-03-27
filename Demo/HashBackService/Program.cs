﻿/* Copyright William Godfrey, 2024. All rights reserved.
 * billpg.com
 */
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using billpg.HashBackService;
using billpg.WebAppTools;
using Newtonsoft.Json.Linq;
using billpg.HashBackCore;
using System.Text;
using System.Security.Cryptography;
using System.Linq.Expressions;
using Microsoft.AspNetCore.Mvc;

/* Announce the service starting. */
Console.WriteLine("Starting HashBackService.");

/* Load port number from config. */
int port = ServiceConfig.LoadRequiredInt("ListenPort");

/* Open a web service. */
var app = WebApplication.Create();
app.Urls.Add($"http://localhost:{port}");

/* Configure various end-points with handlers. */
string redirectHome = ServiceConfig.LoadRequiredString("RedirectHomeTo");
app.MapGet("/", RedirectEndpoints.Found(redirectHome));

/* Configure the hash store. */
app.MapPostWrapped("/hashes", DevHashStoreEndpoints.AddHash);
app.MapGet("/hashes", DevHashStoreEndpoints.GetHashNew);

/* Configure the issuer demo. */
string redirectIssuerDemoDocs = ServiceConfig.LoadRequiredString("RedirectIssuerDemoTo");
app.MapGet("/issuer", RedirectEndpoints.Found(redirectIssuerDemoDocs));
app.MapPostWrapped("/issuer", IssuerDemoEndpoints.RequestPost);

/* Set up the custom error handler. */
app.Use(async (context, next) =>
{
    try { await next(context); }
    catch (Exception ex)
    { ErrorHandler.Handle(ex, context); }
});


app.MapGet("/err", ThrowAnError);
string ThrowAnError()
{
    throw new ApplicationException("hello");
}


app.MapGet("/text", ReturnHello);
string ReturnHello()
    => "hello world";




/* Start running and log. */
Console.WriteLine("Running.");
app.Run();


