package handlers

import (
	"database/sql"
	"shopping-list/db"
	"shopping-list/i18n"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// GetGroupsPage renders the groups management page.
func GetGroupsPage(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return c.Redirect("/login")
	}

	groups, err := db.GetGroupsForUser(user.ID)
	if err != nil {
		return sendError(c, 500, "error.fetch_failed")
	}

	return c.Render("groups", fiber.Map{
		"CurrentUser":  user,
		"Groups":       groups,
		"Translations": i18n.GetAllLocales(),
		"Locales":      i18n.AvailableLocales(),
		"DefaultLang":  i18n.GetDefaultLang(),
	})
}

// GetGroupDetail renders the detail page for a single group.
func GetGroupDetail(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return c.Redirect("/login")
	}

	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return c.Redirect("/groups")
	}

	group, err := db.GetGroupByID(groupID, user.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Redirect("/groups")
		}
		return sendError(c, 500, "error.fetch_failed")
	}
	if group.Role == "" {
		return c.Status(403).SendString("Forbidden")
	}

	members, err := db.GetGroupMembers(groupID)
	if err != nil {
		return sendError(c, 500, "error.fetch_failed")
	}

	invites, err := db.GetGroupInvites(groupID)
	if err != nil {
		return sendError(c, 500, "error.fetch_failed")
	}

	lists, _ := db.GetAllLists(user.ID)
	var groupLists []db.List
	for _, l := range lists {
		if l.GroupID == groupID {
			groupLists = append(groupLists, l)
		}
	}

	return c.Render("group_detail", fiber.Map{
		"CurrentUser":  user,
		"Group":        group,
		"Members":      members,
		"Invites":      invites,
		"Lists":        groupLists,
		"Translations": i18n.GetAllLocales(),
		"Locales":      i18n.AvailableLocales(),
		"DefaultLang":  i18n.GetDefaultLang(),
	})
}

// CreateGroup handles group creation.
func CreateGroup(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	name := strings.TrimSpace(c.FormValue("name"))
	if name == "" {
		return sendError(c, 400, "error.name_required")
	}
	if len(name) > 100 {
		return sendError(c, 400, "error.name_too_long")
	}

	group, err := db.CreateGroup(name, user.ID)
	if err != nil {
		return sendError(c, 500, "error.create_failed")
	}

	if c.Get("HX-Request") == "true" {
		return c.Redirect("/groups/"+strconv.FormatInt(group.ID, 10))
	}
	return c.Redirect("/groups/" + strconv.FormatInt(group.ID, 10))
}

// UpdateGroup renames a group (owner only).
func UpdateGroup(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	if !db.IsGroupOwner(groupID, user.ID) {
		return sendError(c, 403, "error.forbidden")
	}

	name := strings.TrimSpace(c.FormValue("name"))
	if name == "" {
		return sendError(c, 400, "error.name_required")
	}

	if err := db.UpdateGroup(groupID, name); err != nil {
		return sendError(c, 500, "error.update_failed")
	}

	return c.Redirect("/groups/" + c.Params("id"))
}

// DeleteGroup deletes a group (owner only). Lists in the group become group-less.
func DeleteGroup(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	if !db.IsGroupOwner(groupID, user.ID) {
		return sendError(c, 403, "error.forbidden")
	}

	if err := db.DeleteGroup(groupID); err != nil {
		return sendError(c, 500, "error.delete_failed")
	}

	if c.Get("HX-Request") == "true" {
		c.Set("HX-Redirect", "/groups")
		return c.SendStatus(200)
	}
	return c.Redirect("/groups")
}

// InviteMember invites a user to a group by email (owner only).
func InviteMember(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	if !db.IsGroupOwner(groupID, user.ID) {
		return sendError(c, 403, "error.forbidden")
	}

	email := strings.TrimSpace(c.FormValue("email"))
	if email == "" {
		return sendError(c, 400, "error.email_required")
	}

	if err := db.CreateGroupInvite(groupID, user.ID, email); err != nil {
		return sendError(c, 500, "error.invite_failed")
	}

	return c.Redirect("/groups/" + c.Params("id"))
}

// RemoveMember removes a member from a group (owner only, cannot remove self if last owner).
func RemoveMember(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	targetUserID, err := strconv.ParseInt(c.Params("userID"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	if !db.IsGroupOwner(groupID, user.ID) {
		return sendError(c, 403, "error.forbidden")
	}

	if err := db.RemoveGroupMember(groupID, targetUserID); err != nil {
		return sendError(c, 500, "error.remove_failed")
	}

	return c.Redirect("/groups/" + c.Params("id"))
}

// LeaveGroup lets the current user leave a group.
func LeaveGroup(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	groupID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	if err := db.RemoveGroupMember(groupID, user.ID); err != nil {
		return sendError(c, 500, "error.remove_failed")
	}

	if c.Get("HX-Request") == "true" {
		c.Set("HX-Redirect", "/groups")
		return c.SendStatus(200)
	}
	return c.Redirect("/groups")
}

// AcceptInvite accepts a pending group invite.
func AcceptInvite(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	inviteID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	if err := db.AcceptGroupInvite(inviteID, user.ID); err != nil {
		return sendError(c, 500, "error.accept_failed")
	}

	if c.Get("HX-Request") == "true" {
		c.Set("HX-Redirect", "/")
		return c.SendStatus(200)
	}
	return c.Redirect("/")
}

// DeclineInvite declines a pending group invite.
func DeclineInvite(c *fiber.Ctx) error {
	user, ok := GetCurrentUser(c)
	if !ok {
		return sendError(c, 401, "error.unauthorized")
	}

	inviteID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	// Verify invite belongs to this user's email before declining
	inv, err := db.GetGroupInviteByID(inviteID)
	if err != nil {
		return sendError(c, 404, "error.not_found")
	}

	currentUser, _ := db.GetUserByID(user.ID)
	if currentUser == nil || !strings.EqualFold(inv.Email, currentUser.Email) {
		return sendError(c, 403, "error.forbidden")
	}

	if err := db.DeclineGroupInvite(inviteID); err != nil {
		return sendError(c, 500, "error.decline_failed")
	}

	if c.Get("HX-Request") == "true" {
		c.Set("HX-Redirect", "/")
		return c.SendStatus(200)
	}
	return c.Redirect("/")
}

// GetPendingInvites returns pending invites for the current user (used by home page).
func GetPendingInvites(userID int64) []db.GroupInvite {
	user, err := db.GetUserByID(userID)
	if err != nil {
		return nil
	}
	invites, _ := db.GetPendingInvitesForEmail(user.Email)
	return invites
}
