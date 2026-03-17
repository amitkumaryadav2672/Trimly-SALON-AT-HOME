const express = require('express');
const router = express.Router();
const {
  getServices,
  getServiceById,
  createService,
  updateService,
  deleteService,
} = require('../controllers/serviceController');
const { protect } = require('../middlewares/authMiddleware');
// Comment out admin middleware since we don't have an admin yet
// const { onlyAdmin } = require('../middlewares/roleMiddleware');

// Service catalog routes
// Public routes - no authentication required
router.get('/', getServices);
router.get('/:id', getServiceById);

// Protected routes - any authenticated user can manage services (temporary for testing)
router.post('/', protect, createService);  // Removed onlyAdmin
router.patch('/:id', protect, updateService);  // Removed onlyAdmin
router.delete('/:id', protect, deleteService);  // Removed onlyAdmin

module.exports = router;