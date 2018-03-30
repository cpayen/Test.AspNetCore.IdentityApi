using Api.Models;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Api.Data
{
    public class AppDbInitializer
    {
        /// <summary>
        /// Seeds the Identity database with roles and administrator.
        /// </summary>
        /// <param name="userManager"></param>
        /// <param name="roleManager"></param>
        /// <returns></returns>
        public static async Task Seed(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            await SeedRoles(roleManager);
            await SeedUsers(userManager);
        }

        public static async Task SeedRoles(RoleManager<IdentityRole> roleManager)
        {
            var roles = new List<string>()
            {
                "Administrator",
                "User"
            };
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }

        public static async Task SeedUsers(UserManager<AppUser> userManager)
        {
            if (userManager.FindByNameAsync("admin").Result == null)
            {
                var admin = new AppUser()
                {
                    UserName = "admin",
                    Email = "admin@system.net"
                };

                IdentityResult result = userManager.CreateAsync(admin, "Pa$$w0rd").Result;

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(admin, "Administrator");
                }
            }

            if (userManager.FindByNameAsync("user").Result == null)
            {
                var user = new AppUser()
                {
                    UserName = "user",
                    Email = "user@system.net"
                };

                IdentityResult result = userManager.CreateAsync(user, "Pa$$w0rd").Result;

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "User");
                }
            }
        }
    }
}
