package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"shopping-list/db"
	"shopping-list/i18n"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Input length limits
const (
	MaxListNameLength    = 100
	MaxIconLength        = 20 // emoji can be multi-byte
	MaxSectionNameLength = 100
	MaxItemNameLength    = 200
	MaxDescriptionLength = 500
)

// GetListsPage returns the homepage with all lists
func GetListsPage(c *fiber.Ctx) error {
	userID := GetCurrentUserID(c)
	user, _ := GetCurrentUser(c)

	lists, err := db.GetAllLists(userID)
	if err != nil {
		return sendError(c, 500, "error.fetch_failed")
	}

	templates, _ := db.GetAllTemplates()

	var pendingInvites []db.GroupInvite
	if userID > 0 {
		pendingInvites = GetPendingInvites(userID)
	}

	return c.Render("home", fiber.Map{
		"CurrentUser":    user,
		"Lists":          lists,
		"Templates":      templates,
		"PendingInvites": pendingInvites,
		"Translations":   i18n.GetAllLocales(),
		"Locales":        i18n.AvailableLocales(),
		"DefaultLang":    i18n.GetDefaultLang(),
	})
}

// GetListView returns a single list with its items
func GetListView(c *fiber.Ctx) error {
	userID := GetCurrentUserID(c)
	user, _ := GetCurrentUser(c)

	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return c.Redirect("/")
	}

	list, err := db.GetListByID(id, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Redirect("/")
		}
		log.Printf("Error fetching list %d: %v", id, err)
		return sendError(c, 500, "error.database_error")
	}

	// Set this list as active
	db.SetActiveList(id)

	sections, err := db.GetSectionsByList(id)
	if err != nil {
		return sendError(c, 500, "error.fetch_failed")
	}

	stats := db.GetListStats(id)
	lists, _ := db.GetAllLists(userID)

	var userGroups []db.Group
	if userID > 0 {
		userGroups, _ = db.GetGroupsForUser(userID)
	}

	return c.Render("list", fiber.Map{
		"CurrentUser":   user,
		"List":          list,
		"Lists":         lists,
		"Sections":      sections,
		"Stats":         stats,
		"ShowCompleted": list.ShowCompleted,
		"UserGroups":    userGroups,
		"Translations":  i18n.GetAllLocales(),
		"Locales":       i18n.AvailableLocales(),
		"DefaultLang":   i18n.GetDefaultLang(),
	})
}

// GetLists returns all lists (JSON API)
func GetLists(c *fiber.Ctx) error {
	userID := GetCurrentUserID(c)
	lists, err := db.GetAllLists(userID)
	if err != nil {
		return sendError(c, 500, "error.fetch_failed")
	}

	if c.Query("format") == "json" {
		return c.JSON(lists)
	}

	return c.Redirect("/")
}

// CreateList creates a new shopping list
func CreateList(c *fiber.Ctx) error {
	name := c.FormValue("name")
	if name == "" {
		return sendError(c, 400, "error.name_required")
	}
	if len(name) > MaxListNameLength {
		return sendError(c, 400, "error.name_too_long")
	}
	if name == "[HISTORY]" {
		return sendError(c, 400, "common.reserved_name")
	}

	// Check for duplicate name
	exists, err := db.ListNameExists(name, 0)
	if err != nil {
		return sendError(c, 500, "error.check_failed")
	}
	if exists {
		return sendError(c, 409, "list.name_exists")
	}

	icon := c.FormValue("icon")
	if icon == "" {
		icon = "🛒"
	}
	if len(icon) > MaxIconLength {
		return sendError(c, 400, "error.icon_too_long")
	}

	ownerID := GetCurrentUserID(c)
	list, err := db.CreateList(name, icon, ownerID)
	if err != nil {
		return sendError(c, 500, "error.create_failed")
	}

	// Broadcast to WebSocket clients
	BroadcastUpdate("list_created", list)

	// Return the new list item partial for HTMX
	return c.Render("partials/list_item", fiber.Map{
		"List": list,
	}, "")
}

// UpdateList updates a list's name and icon
func UpdateList(c *fiber.Ctx) error {
	userID := GetCurrentUserID(c)
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}
	if !db.UserCanAccessList(userID, id) {
		return sendError(c, 403, "error.forbidden")
	}

	name := c.FormValue("name")
	if name == "" {
		return sendError(c, 400, "error.name_required")
	}
	if len(name) > MaxListNameLength {
		return sendError(c, 400, "error.name_too_long")
	}
	if name == "[HISTORY]" {
		return sendError(c, 400, "common.reserved_name")
	}

	// Check for duplicate name (excluding current list)
	exists, err := db.ListNameExists(name, id)
	if err != nil {
		return sendError(c, 500, "error.check_failed")
	}
	if exists {
		return sendError(c, 409, "list.name_exists")
	}

	icon := c.FormValue("icon")
	if len(icon) > MaxIconLength {
		return sendError(c, 400, "error.icon_too_long")
	}

	list, err := db.UpdateList(id, name, icon)
	if err != nil {
		return sendError(c, 500, "error.update_failed")
	}

	// Broadcast to WebSocket clients
	BroadcastUpdate("list_updated", list)

	// Return updated list item partial
	return c.Render("partials/list_item", fiber.Map{
		"List": list,
	}, "")
}

// DeleteList deletes a shopping list
func DeleteList(c *fiber.Ctx) error {
	userID := GetCurrentUserID(c)
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}
	if !db.UserCanAccessList(userID, id) {
		return sendError(c, 403, "error.forbidden")
	}

	err = db.DeleteList(id)
	if err != nil {
		return c.Status(400).SendString(err.Error())
	}

	// Broadcast to WebSocket clients
	BroadcastUpdate("list_deleted", map[string]int64{"id": id})

	// Return empty string (HTMX will remove the element)
	return c.SendString("")
}

// SetActiveList sets a list as active
func SetActiveList(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	err = db.SetActiveList(id)
	if err != nil {
		return sendError(c, 500, "error.check_failed")
	}

	// Broadcast to WebSocket clients
	BroadcastUpdate("list_activated", map[string]int64{"id": id})

	// Check if this is an AJAX request (HTMX or fetch)
	isAjax := c.Get("HX-Request") != "" || c.Get("X-Requested-With") != ""
	if !isAjax {
		return c.Redirect(fmt.Sprintf("/lists/%d", id))
	}

	// Check if this is from the lists management page or main page
	currentURL := c.Get("HX-Current-URL")
	referer := c.Get("Referer")
	isListsPage := strings.Contains(currentURL, "/lists") || strings.Contains(referer, "/lists")

	if !isListsPage {
		c.Set("HX-Redirect", fmt.Sprintf("/lists/%d", id))
		return c.SendString("")
	}

	// Return updated lists for the management page
	return returnAllLists(c)
}

// MoveListUp moves a list up in order
func MoveListUp(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	err = db.MoveListUp(id)
	if err != nil {
		return sendError(c, 500, "error.move_failed")
	}

	BroadcastUpdate("lists_reordered", nil)
	return c.SendStatus(200)
}

// MoveListDown moves a list down in order
func MoveListDown(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	err = db.MoveListDown(id)
	if err != nil {
		return sendError(c, 500, "error.move_failed")
	}

	BroadcastUpdate("lists_reordered", nil)
	return c.SendStatus(200)
}

// Helper to return all lists as HTML partials
func returnAllLists(c *fiber.Ctx) error {
	userID := GetCurrentUserID(c)
	lists, err := db.GetAllLists(userID)
	if err != nil {
		return sendError(c, 500, "error.fetch_failed")
	}

	activeList, _ := db.GetActiveList(userID)

	return c.Render("partials/lists_container", fiber.Map{
		"Lists":      lists,
		"ActiveList": activeList,
	}, "")
}

// TransferListToGroup moves a list to a group (or makes it private with group_id=0).
func TransferListToGroup(c *fiber.Ctx) error {
	userID := GetCurrentUserID(c)
	listID, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return sendError(c, 400, "error.invalid_id")
	}

	if !db.UserCanAccessList(userID, listID) {
		return sendError(c, 403, "error.forbidden")
	}

	groupIDStr := c.FormValue("group_id")
	groupID, _ := strconv.ParseInt(groupIDStr, 10, 64)

	// When making private, verify user is the owner
	if groupID == 0 {
		list, err := db.GetListByID(listID, 0)
		if err != nil || list.OwnerID != userID {
			return sendError(c, 403, "error.forbidden")
		}
	} else {
		// Verify user is member of the target group
		if !db.IsGroupMember(groupID, userID) {
			return sendError(c, 403, "error.forbidden")
		}
	}

	if err := db.TransferListToGroup(listID, groupID, userID); err != nil {
		return sendError(c, 500, "error.update_failed")
	}

	BroadcastUpdate("list_updated", map[string]int64{"id": listID})

	if c.Get("HX-Request") == "true" {
		c.Set("HX-Redirect", "/lists/"+c.Params("id"))
		return c.SendStatus(200)
	}
	return c.Redirect("/lists/" + c.Params("id"))
}

// ToggleShowCompleted toggles the show_completed setting for a list
func ToggleShowCompleted(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return c.Status(400).SendString("Invalid ID")
	}

	list, err := db.ToggleListShowCompleted(id)
	if err != nil {
		return c.Status(500).SendString("Failed to toggle show completed")
	}

	// Broadcast to WebSocket clients
	BroadcastUpdate("list_updated", list)

	// Return the updated sections list
	sections, err := db.GetSectionsByList(id)
	if err != nil {
		return c.Status(500).SendString("Failed to fetch sections")
	}

	return c.Render("partials/sections_list", fiber.Map{
		"Sections":      sections,
		"ShowCompleted": list.ShowCompleted,
	}, "")
}

// sectionRenderMap builds the template data map for rendering a single section partial
func sectionRenderMap(section *db.Section, userID int64) fiber.Map {
	return fiber.Map{
		"Section":       section,
		"Sections":      getSectionsForDropdown(userID),
		"ShowCompleted": db.GetShowCompletedForSection(section.ID),
	}
}
