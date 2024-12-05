using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using WebApp_DistributedSignOut_DotNet.Controllers;
using Microsoft.Owin.Security;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Principal;

namespace WebApp_DistributedSignOut_DotNet.Tests.Controllers
{
    [TestClass]
    public class AccountControllerTests
    {
        private Mock<HttpContextBase> _mockHttpContext;
        private Mock<IAuthenticationManager> _mockAuthManager;
        private Mock<HttpSessionStateBase> _mockSession;
        private AccountController _controller;
        private const string AADTenantId = "test-tenant-id";

        [TestInitialize]
        public void Setup()
        {
            // Setup mocks
            _mockHttpContext = new Mock<HttpContextBase>();
            _mockAuthManager = new Mock<IAuthenticationManager>();
            _mockSession = new Mock<HttpSessionStateBase>();

            // Setup controller context
            var controllerContext = new Mock<ControllerContext>();
            controllerContext.Setup(x => x.HttpContext).Returns(_mockHttpContext.Object);
            _mockHttpContext.Setup(c => c.Session).Returns(_mockSession.Object);

            _controller = new AccountController();
            _controller.ControllerContext = controllerContext.Object;
        }

        [TestMethod]
        public void SignOut_ShouldClearSessionAndRedirectToHome()
        {
            // Arrange
            SetupAuthenticatedUser();

            // Act
            var result = _controller.SignOut() as RedirectToRouteResult;

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("Home", result.RouteValues["controller"]);
            Assert.AreEqual("Index", result.RouteValues["action"]);
            _mockSession.Verify(s => s.Abandon(), Times.Once);
        }

        [TestMethod]
        public async Task SingleSignOut_ShouldNotifyOtherAppsAndRedirectToHome()
        {
            // Arrange
            SetupAuthenticatedUser();
            var signOutNotification = new Mock<ISignOutNotification>();
            _mockAuthManager.Setup(a => a.SignOut(It.IsAny<string[]>()))
                          .Callback(() => signOutNotification.Object.NotifyApplications(AADTenantId));

            // Act
            var result = await _controller.SingleSignOut() as RedirectToRouteResult;

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("Home", result.RouteValues["controller"]);
            _mockAuthManager.Verify(a => a.SignOut(It.Is<string[]>(s => s[0] == "OpenIdConnect")), Times.Once);
            signOutNotification.Verify(n => n.NotifyApplications(AADTenantId), Times.Once);
        }

        [TestMethod]
        public void SessionChanged_WhenSignedOutFromOtherApp_ShouldDisplayNotification()
        {
            // Arrange
            SetupAuthenticatedUser();
            var signOutMessage = "You have been signed out because you signed out of another application.";
            _mockSession.Setup(s => s.Add("SignOutMessage", signOutMessage));

            // Act
            var result = _controller.SessionChanged() as ViewResult;

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("SessionChanged", result.ViewName);
            Assert.IsTrue(result.ViewData.ContainsKey("SignOutMessage"));
            Assert.AreEqual(signOutMessage, result.ViewData["SignOutMessage"]);
        }

        [TestMethod]
        public void HandleExternalSignOut_ShouldProcessTenantWideSignOut()
        {
            // Arrange
            SetupAuthenticatedUser();
            var externalSignOutNotification = new ExternalSignOutNotification
            {
                TenantId = AADTenantId,
                SignOutInitiator = "OtherApp"
            };

            // Act
            var result = _controller.HandleExternalSignOut(externalSignOutNotification) as ViewResult;

            // Assert
            Assert.IsNotNull(result);
            _mockSession.Verify(s => s.Abandon(), Times.Once);
            Assert.IsTrue(result.ViewData.ContainsKey("SignOutMessage"));
            Assert.IsTrue(result.ViewData["SignOutMessage"].ToString()
                .Contains("signed out of another application"));
        }

        [TestMethod]
        public void SignIn_ShouldRedirectToAzureAD()
        {
            // Arrange
            var mockOwin = new Mock<IOwinContext>();
            mockOwin.Setup(o => o.Authentication).Returns(_mockAuthManager.Object);

            // Act
            var result = _controller.SignIn() as ChallengeResult;

            // Assert
            Assert.IsNotNull(result);
            _mockAuthManager.Verify(a =>
                a.Challenge(It.IsAny<AuthenticationProperties>(),
                It.Is<string[]>(s => s[0] == "OpenIdConnect")),
                Times.Once);
        }

        private void SetupAuthenticatedUser()
        {
            var claims = new List<Claim>
            {
                new Claim("tid", AADTenantId),
                new Claim(ClaimTypes.Name, "testuser@domain.com")
            };
            var identity = new ClaimsIdentity(claims, "OpenIdConnect");
            var principal = new ClaimsPrincipal(identity);

            _mockHttpContext.Setup(c => c.User).Returns(principal);
            _mockHttpContext.Setup(c => c.Request.IsAuthenticated).Returns(true);
        }
    }

    // Mock interfaces and classes for testing
    public interface ISignOutNotification
    {
        void NotifyApplications(string tenantId);
    }

    public class ExternalSignOutNotification
    {
        public string TenantId { get; set; }
        public string SignOutInitiator { get; set; }
    }

    public class ChallengeResult : HttpUnauthorizedResult
    {
        public string LoginProvider { get; set; }
        public AuthenticationProperties Properties { get; set; }

        public ChallengeResult(string provider, AuthenticationProperties properties)
        {
            LoginProvider = provider;
            Properties = properties;
        }
    }
}
